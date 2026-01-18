param (
    [string]$AZSubscription = "SubscriptionName",
    [string]$SubscriptionId = '00000000-0000-0000-0000-000000000000',
    [string]$ResourceGroupName = "ResourceGroupName",
    [string]$Location = "UK South",
    [string]$VNetName = "VNET Name",          # Will be created if missing
    [string]$VNetAddressSpace = "10.0.0.0/16",                         # Adjust to suit
    [string]$GatewaySubnetName = "GatewaySubnet",                        # Must be exactly 'GatewaySubnet'
    [string]$GatewaySubnetPrefix = "10.0.1.0/27",                       # Adjust to suit
    [string]$GatewayName = "Gateway",
    [string]$PublicIpName = "IP Name",
    [string]$GatewaySku_Basic = "Basic",
    [string]$PublicIpSku_Basic = "Basic",      # Dynamic allocation only
    [string]$PublicIpAlloc_Basic = "Dynamic",
    [string]$GatewaySku_Modern = "VpnGw1AZ",   # Zone-redundant
    [string]$PublicIpSku_Modern = "Standard",   # Static + zone-redundant
    [string]$PublicIpAlloc_Modern = "Static",
    [array]$PublicIpZones = @(1,2,3),     # Zone-redundant
    [string]$Lng1Name = "Connection Name",
    [string]$Lng1PublicIp = "111.111.111.111",         # On-prem WAN public IP for Site 1
    [array]$Lng1AddressSpaces = @("172.16.20.0/24","192.168.0.0/24","192.168.20.0/24","172.16.25.0/24"),    # One or more on-prem LAN prefixes
    [string]$Lng2Name = "Connection Name Two",
    [string]$Lng2PublicIp = "222.222.222.222",          # On-prem WAN public IP for Site 2
    [array]$Lng2AddressSpaces = @("172.16.100.0/24"),     # One or more on-prem LAN prefixes
    [string]$VpnSharedKey_Site1 = "SECRET",
    [string]$VpnSharedKey_Site2 = "SECRET",
    [string]$DNSLocation = "uksouth",
    [string]$OutboundSubnetName = 'dns-outbound-subnet',
    [string]$OutboundPrefix = '10.0.1.0/28',
    [string]$ResolverName = 'DNSPrivateEndpoint',
    [string]$FallbackResolverName = 'dnsresolver',
    [string]$OutboundEndpointName = 'outbound',
    [string]$RuleSetName          = 'ruleset',
    [string]$ForwardRuleName      = 'domain-name',
    [string]$DomainToForward      = 'domain.name.',
    [string[]]$TargetDnsIps = @('1.1.1.1','2.2.2.2'),
    [string[]]$SubnetNames = @('Windows365','AVD'),
    [string]$NatGatewayName = 'uksouth-nat',
    [string]$NATPublicIpName = 'uksouth-nat-pip',
    [int]$IdleTimeoutMinutes = 15,
    [string]$Mode = 'Teardown',
    [switch]$RemovePublicIpOnTearDown
)
<#
Not used:
$VNetAddressSpace
$GatewaySubnetPrefix
$GatewaySku_Basic
$PublicIpSku_Basic
$PublicIpAlloc_Basic
$Lng1PublicIp
$Lng1AddressSpaces
$Lng2PublicIp
$Lng2AddressSpaces
#>

# Authenticate using the Automation Account's Managed Identity
Connect-AzAccount -Identity | Out-Null
Set-AzContext -Subscription (Get-AzContext).Subscription

# ====== Subscription context (optional if already set) ======
Set-AzContext -Subscription $AZSubscription

# Remove connections first (idempotent)
Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue `
| Where-Object { $_.VirtualNetworkGateway1.Id -like "*$GatewayName" } `
| ForEach-Object {
    Write-Host "Removing connection $($_.Name)..."
    Remove-AzVirtualNetworkGatewayConnection -Name $_.Name -ResourceGroupName $ResourceGroupName -Force
}

# Remove the gateway (PIP is preserved because it is a separate resource)
if (Get-AzVirtualNetworkGateway -Name $GatewayName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue) {
    Write-Host "Removing VPN gateway '$GatewayName'..."
    Remove-AzVirtualNetworkGateway -Name $GatewayName -ResourceGroupName $ResourceGroupName -Force
} else {
    Write-Host "Gateway '$GatewayName' not found; nothing to remove."
}


# Destroy DNS Resolver
# --- Constants / helpers (API versions)
$apiDns  = "2022-07-01"   # dnsResolvers & dnsForwardingRulesets
$apiVNet = "2023-09-01"   # virtualNetworks
$rgId    = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
function Invoke-ArmGet {
  param(
    [Parameter(Mandatory)][string] $ResourceId,
    [Parameter(Mandatory)][string] $ApiVersion
  )
  Invoke-AzRestMethod -Method GET -Path "$ResourceId?api-version=$ApiVersion"
}
function Invoke-ArmDelete {
  param(
    [Parameter(Mandatory)][string] $ResourceId,
    [Parameter(Mandatory)][string] $ApiVersion
  )
  Invoke-AzRestMethod -Method DELETE -Path "$ResourceId?api-version=$ApiVersion" -ErrorAction SilentlyContinue | Out-Null
}
function Invoke-ArmPut {
  param(
    [Parameter(Mandatory)][string] $ResourceId,
    [Parameter(Mandatory)][string] $ApiVersion,
    [Parameter(Mandatory)][hashtable] $Body
  )
  $json = $Body | ConvertTo-Json -Depth 50
  Invoke-AzRestMethod -Method PUT -Path "$ResourceId?api-version=$ApiVersion" -Payload $json | Out-Null
}
function Convert-FromArmResponse {
  param([object]$Resp)
  if ($Resp.Content) { return ($Resp.Content | ConvertFrom-Json) } else { return $null }
}
# --- Enumerations / accessors
function Get-ResolversInRg {
  $resp = Invoke-ArmGet -ResourceId "$rgId/providers/Microsoft.Network/dnsResolvers" -ApiVersion $apiDns
  (Convert-FromArmResponse $resp)?.value
}
function Get-EndpointsForResolver {
  param([Parameter(Mandatory)][string]$ResolverId)
  $out = (Convert-FromArmResponse (Invoke-ArmGet -ResourceId "$ResolverId/outboundEndpoints" -ApiVersion $apiDns))?.value
  $inn = (Convert-FromArmResponse (Invoke-ArmGet -ResourceId "$ResolverId/inboundEndpoints"  -ApiVersion $apiDns))?.value
  [PSCustomObject]@{ Outbound = $out; Inbound = $inn }
}
function Get-RulesetsInRg {
  $resp = Invoke-ArmGet -ResourceId "$rgId/providers/Microsoft.Network/dnsForwardingRulesets" -ApiVersion $apiDns
  (Convert-FromArmResponse $resp)?.value
}
function Get-RulesForRuleset {
  param([Parameter(Mandatory)][string]$RulesetId)
  (Convert-FromArmResponse (Invoke-ArmGet -ResourceId "$RulesetId/forwardingRules" -ApiVersion $apiDns))?.value
}
function Get-VnetLinksForRuleset {
  param([Parameter(Mandatory)][string]$RulesetId)
  (Convert-FromArmResponse (Invoke-ArmGet -ResourceId "$RulesetId/virtualNetworkLinks" -ApiVersion $apiDns))?.value
}
# --- Core removal
function Remove-ResolverStack {
  param([Parameter(Mandatory)][string]$ResolverName)

  $resolverId = "$rgId/providers/Microsoft.Network/dnsResolvers/$ResolverName"

  # Exists?
  $resolverResp = Invoke-ArmGet -ResourceId $resolverId -ApiVersion $apiDns
  $resolver     = Convert-FromArmResponse $resolverResp
  if (-not $resolver) {
    Write-Verbose "Resolver '$ResolverName' not found; skipping."
    return
  }

  Write-Verbose "Processing resolver '$ResolverName'..."

  # 1) Gather endpoints
  $eps = Get-EndpointsForResolver -ResolverId $resolverId
  $outboundIds = @()
  if ($eps.Outbound) { $outboundIds = @($eps.Outbound | ForEach-Object { $_.id }) }

  # 2) Identify forwarding rulesets in RG that reference these outbound endpoints
  $allRs = Get-RulesetsInRg
  $ruleSetsToRemove = @()
  foreach ($rs in $allRs) {
    $epRefs = $rs.properties.dnsResolverOutboundEndpoints
    if ($epRefs) {
      if ($epRefs | Where-Object { $outboundIds -contains $_.id }) {
        $ruleSetsToRemove += $rs
      }
    }
  }

  # 3) For each matched ruleset: delete rules -> links -> ruleset
  foreach ($rs in $ruleSetsToRemove) {
    $rsId   = $rs.id
    $rsName = $rs.name
    Write-Verbose "Tearing down forwarding ruleset '$rsName' (references '$ResolverName')."

    $rules = Get-RulesForRuleset -RulesetId $rsId
    foreach ($rule in ($rules | Sort-Object name)) {
      Write-Verbose " - Removing rule '$($rule.name)'"
      Invoke-ArmDelete -ResourceId "$rsId/forwardingRules/$($rule.name)" -ApiVersion $apiDns
    }

    $links = Get-VnetLinksForRuleset -RulesetId $rsId
    foreach ($lnk in ($links | Sort-Object name)) {
      Write-Verbose " - Removing VNet link '$($lnk.name)'"
      Invoke-ArmDelete -ResourceId "$rsId/virtualNetworkLinks/$($lnk.name)" -ApiVersion $apiDns
    }

    Write-Verbose " - Removing ruleset '$rsName'"
    Invoke-ArmDelete -ResourceId $rsId -ApiVersion $apiDns
  }

  # 4) Remove endpoints (outbound then inbound)
  if ($eps.Outbound) {
    foreach ($ep in $eps.Outbound) {
      Write-Verbose "Removing outbound endpoint '$($ep.name)'"
      Invoke-ArmDelete -ResourceId "$resolverId/outboundEndpoints/$($ep.name)" -ApiVersion $apiDns
    }
  }
  if ($eps.Inbound) {
    foreach ($ep in $eps.Inbound) {
      Write-Verbose "Removing inbound endpoint '$($ep.name)'"
      Invoke-ArmDelete -ResourceId "$resolverId/inboundEndpoints/$($ep.name)" -ApiVersion $apiDns
    }
  }

  # 5) Remove resolver
  Write-Verbose "Removing resolver '$ResolverName'"
  Invoke-ArmDelete -ResourceId $resolverId -ApiVersion $apiDns
}
# --- Execute for all requested resolvers
foreach ($name in $ResolversToRemove) {
  Remove-ResolverStack -ResolverName $name
}
# --- Optional: remove the delegated subnet from the VNet
if ($RemoveSubnet) {
  $vnetId = "$rgId/providers/Microsoft.Network/virtualNetworks/$VNetName"
  $vnet   = Convert-FromArmResponse (Invoke-ArmGet -ResourceId $vnetId -ApiVersion $apiVNet)

  if ($vnet) {
    $existing = @($vnet.properties.subnets)
    $newList  = @($existing | Where-Object { $_.name -ne $OutboundSubnetName })

    if ($newList.Count -ne $existing.Count) {
      Write-Verbose "Removing subnet '$OutboundSubnetName' from VNet '$VNetName'..."
      $body = @{
        location   = $vnet.location
        properties = $vnet.properties
      }
      $body.properties.subnets = $newList
      Invoke-ArmPut -ResourceId $vnetId -ApiVersion $apiVNet -Body $body
    } else {
      Write-Verbose "Subnet '$OutboundSubnetName' not present; nothing to remove."
    }
  } else {
    Write-Verbose "VNet '$VNetName' not found; cannot remove subnet."
  }
}
Write-Output ("Teardown complete for resolvers: " + ($ResolversToRemove -join ', '))
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
Write-Verbose "Authenticating with Managed Identity..."
Connect-AzAccount -Identity | Out-Null
Set-AzContext -Subscription $SubscriptionId | Out-Null
Import-Module Az.Network -ErrorAction Stop
Import-Module Az.DnsResolver -ErrorAction Stop
try {
    # --- 1. Confirm resolver exists ---
    $resolver = Get-AzDnsResolver -ResourceGroupName $ResourceGroupName -Name $ResolverName -ErrorAction SilentlyContinue
    if (-not $resolver) {
        Write-Warning "Resolver '$ResolverName' not found. Nothing to remove."
        return
    }

    # --- 2. Remove forwarding rules and ruleset ---
    Write-Verbose "Checking for forwarding ruleset '$RuleSetName'..."
    $ruleSet = Get-AzDnsForwardingRuleset -ResourceGroupName $ResourceGroupName -Name $RuleSetName -ErrorAction SilentlyContinue
    if ($ruleSet) {
        $rule = Get-AzDnsForwardingRulesetForwardingRule -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $ForwardRuleName -ErrorAction SilentlyContinue
        if ($rule) {
            Write-Verbose "Removing forwarding rule '$ForwardRuleName'..."
            Remove-AzDnsForwardingRulesetForwardingRule -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $ForwardRuleName -ErrorAction SilentlyContinue
        }

        # Remove all VNet links before deleting ruleset
        Write-Verbose "Removing any VNet links for '$RuleSetName'..."
        $links = Get-AzDnsForwardingRulesetVirtualNetworkLink -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -ErrorAction SilentlyContinue
        foreach ($link in $links) {
            Write-Verbose "Deleting VNet link '$($link.Name)'..."
            Remove-AzDnsForwardingRulesetVirtualNetworkLink -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $link.Name -ErrorAction SilentlyContinue
        }

        Write-Verbose "Deleting forwarding ruleset '$RuleSetName'..."
        Remove-AzDnsForwardingRuleset -ResourceGroupName $ResourceGroupName -Name $RuleSetName -ErrorAction SilentlyContinue
    }

    # --- 3. Remove outbound endpoint ---
    $outEp = Get-AzDnsResolverOutboundEndpoint -ResourceGroupName $ResourceGroupName -DnsResolverName $ResolverName -Name $OutboundEndpointName -ErrorAction SilentlyContinue
    if ($outEp) {
        Write-Verbose "Deleting outbound endpoint '$OutboundEndpointName'..."
        Remove-AzDnsResolverOutboundEndpoint -ResourceGroupName $ResourceGroupName -DnsResolverName $ResolverName -Name $OutboundEndpointName -ErrorAction SilentlyContinue
    }

    # --- 4. Remove resolver itself ---
    Write-Verbose "Deleting resolver '$ResolverName'..."
    Start-Sleep -Seconds 60
    Remove-AzDnsResolver -ResourceGroupName $ResourceGroupName -Name $ResolverName

    # --- 5. Optionally remove the subnet ---
#    if ($RemoveSubnet) {
        Write-Verbose "Removing delegated subnet '$OutboundSubnetName' from VNet '$VNetName'..."
        $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if ($vnet) {
            $vnet.Subnets.RemoveAll({ $_.Name -eq $OutboundSubnetName }) | Out-Null
            $vnet | Set-AzVirtualNetwork | Out-Null
        } else {
            Write-Warning "VNet '$VNetName' not found – cannot remove subnet."
        }
 #   }

 # TH
$subnetParams = @{
  Name           = $OutboundSubnetName
  VirtualNetwork = $vnet
}
Remove-AzVirtualNetworkSubnetConfig @subnetParams | Set-AzVirtualNetwork
 # TH

    Write-Output "Teardown complete for resolver '$ResolverName'."
}
catch {
    Write-Error $_.Exception.Message
    throw
}


# NAT Gateway Utility

function Test-ModuleAvailable {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' is not available."
  }
  if (-not (Get-Module -Name $Name)) {
    Import-Module $Name -ErrorAction Stop | Out-Null
  }
}

function Get-VirtualNetwork {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName
  )
  Get-AzVirtualNetwork -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
}

function Get-SubnetConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,
    [Parameter(Mandatory)][string]$SubnetName
  )
  Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VirtualNetwork -Name $SubnetName -ErrorAction Stop
}

function Get-PublicIp {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName
  )
  Get-AzPublicIpAddress -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
}

function New-PersistentPublicIp {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$DNSLocation
  )
  if ($PSCmdlet.ShouldProcess("Public IP '$Name'","Create Standard Static")) {
    New-AzPublicIpAddress -Name $Name -ResourceGroupName $ResourceGroupName -Location $DNSLocation -Sku Standard -AllocationMethod Static
  }
}

function Get-NatGatewaySafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName
  )
  Get-AzNatGateway -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
}

function New-OrUpdateNatGateway {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$DNSLocation,
    [Parameter(Mandatory)][int]$IdleTimeoutMinutes,
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSPublicIpAddress]$PublicIp
  )

  $existing = Get-NatGatewaySafe -Name $Name -ResourceGroupName $ResourceGroupName
  if ($existing) {
    # Ensure PIP is referenced
    $pipIds = @($existing.PublicIpAddresses | ForEach-Object { $_.Id })
    if ($PublicIp.Id -notin $pipIds) {
      if ($PSCmdlet.ShouldProcess("NAT Gateway '$Name'","Associate Public IP '$($PublicIp.Name)'")) {
        $existing.PublicIpAddresses = @($pipIds + $PublicIp.Id | Select-Object -Unique)
        $existing = Set-AzNatGateway -NatGateway $existing
      }
    }
    return $existing
  }

  if ($PSCmdlet.ShouldProcess("NAT Gateway '$Name'","Create (IdleTimeout=$IdleTimeoutMinutes)")) {
    New-AzNatGateway -Name $Name `
                     -ResourceGroupName $ResourceGroupName `
                     -Location $DNSLocation `
                     -Sku Standard `
                     -IdleTimeoutInMinutes $IdleTimeoutMinutes `
                     -PublicIpAddress @($PublicIp)
  }
}

function Set-SubnetNatAssociation {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet,
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSNatGateway]$NatGateway
  )
  $null = Set-AzVirtualNetworkSubnetConfig -VirtualNetwork $VirtualNetwork -Name $Subnet.Name -AddressPrefix $Subnet.AddressPrefix -NatGateway $NatGateway
  if ($PSCmdlet.ShouldProcess("Subnet '$($Subnet.Name)'","Associate NAT Gateway '$($NatGateway.Name)'")) {
    $VirtualNetwork | Set-AzVirtualNetwork | Out-Null
  }
}

function Clear-SubnetNatAssociation {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,
    [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet
  )
  $null = Set-AzVirtualNetworkSubnetConfig -VirtualNetwork $VirtualNetwork -Name $Subnet.Name -AddressPrefix $Subnet.AddressPrefix -NatGateway $null
  if ($PSCmdlet.ShouldProcess("Subnet '$($Subnet.Name)'","Disassociate NAT Gateway")) {
    $VirtualNetwork | Set-AzVirtualNetwork | Out-Null
  }
}

function Remove-NatGatewayIfExists {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName
  )
  $nat = Get-NatGatewaySafe -Name $Name -ResourceGroupName $ResourceGroupName
  if (-not $nat) { return }
  if ($PSCmdlet.ShouldProcess("NAT Gateway '$Name'","Remove")) {
    Remove-AzNatGateway -Name $Name -ResourceGroupName $ResourceGroupName -Force
  }
}

function Remove-PublicIpIfExists {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroupName
  )
  $pip = Get-PublicIp -Name $Name -ResourceGroupName $ResourceGroupName
  if (-not $pip) { return }
  if ($PSCmdlet.ShouldProcess("Public IP '$Name'","Remove")) {
    Remove-AzPublicIpAddress -Name $Name -ResourceGroupName $ResourceGroupName -Force
  }
}


# ====== NAT Gateway ======
  Write-Verbose ("Target subnets: {0}" -f ($SubnetNames -join ', '))

  $vnet = Get-VirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName

  if ($Mode -eq 'Deploy') {
    # Public IP (persisted)
    $pip = Get-PublicIp -Name $NATPublicIpName -ResourceGroupName $ResourceGroupName
    if (-not $pip) {
      $pip = New-PersistentPublicIp -Name $NATPublicIpName -ResourceGroupName $ResourceGroupName -Location $DNSLocation
    }

    # NAT Gateway
    $nat = New-OrUpdateNatGateway -Name $NatGatewayName `
                                  -ResourceGroupName $ResourceGroupName `
                                  -DNSLocation $DNSLocation `
                                  -IdleTimeoutMinutes $IdleTimeoutMinutes `
                                  -PublicIp $pip

    # Associate to each subnet
    foreach ($subnetName in $SubnetNames) {
      $subnet = Get-SubnetConfig -VirtualNetwork $vnet -SubnetName $subnetName
      Set-SubnetNatAssociation -VirtualNetwork $vnet -Subnet $subnet -NatGateway $nat
    }

    $pipNames = ($nat.PublicIpAddresses | ForEach-Object { $_.Id.Split('/')[-1] }) -join ', '
    Write-Host ("SUCCESS: NAT Gateway '{0}' is associated to subnets [{1}]. Outbound IP(s): {2}" -f $NatGatewayName, ($SubnetNames -join ', '), $pipNames)
  }
  else {
    # Disassociate NATGW from each subnet
    foreach ($subnetName in $SubnetNames) {
      $subnet = Get-SubnetConfig -VirtualNetwork $vnet -SubnetName $subnetName
      Clear-SubnetNatAssociation -VirtualNetwork $vnet -Subnet $subnet
    }

    # Remove NAT Gateway, optionally Public IP
    Remove-NatGatewayIfExists -Name $NatGatewayName -ResourceGroupName $ResourceGroupName

    if ($RemovePublicIpOnTearDown) {
      Remove-PublicIpIfExists -Name $NATPublicIpName -ResourceGroupName $ResourceGroupName
      Write-Host ("Teardown complete. NAT Gateway '{0}' and Public IP '{1}' removed." -f $NatGatewayName, $NATPublicIpName)
    } else {
      Write-Host ("Teardown complete. NAT Gateway '{0}' removed. Public IP '{1}' retained (persistent)." -f $NatGatewayName, $NATPublicIpName)
    }
  }
