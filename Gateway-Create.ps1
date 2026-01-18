param (
    [string]$AZSubscription = "SubscriptionName",
    [string]$SubscriptionId = '00000000-0000-0000-0000-000000000000',
    [string]$ResourceGroupName = "ResourceGroupName",
    [string]$Location = "UK South",
    [string]$VNetName = "VNET Name",          # Will be created if missing
    [string]$VNetAddressSpace = "10.0.0.0/16",                         # Adjust to suit
    [string]$GatewaySubnetName = "GatewaySubnet",                        # Must be exactly 'GatewaySubnet'
    [string]$GatewaySubnetPrefix = "10.0.1.0/27",                       # Adjust to suit
    [string]$GatewayName = "VirtualNetworkGateway",
    [string]$PublicIpName = "Gateway-PIP",
    [string]$GatewaySku_Basic = "Basic",
    [string]$PublicIpSku_Basic = "Basic",      # Dynamic allocation only
    [string]$PublicIpAlloc_Basic = "Dynamic",
    [string]$GatewaySku_Modern = "VpnGw1AZ",   # Zone-redundant
    [string]$PublicIpSku_Modern = "Standard",   # Static + zone-redundant
    [string]$PublicIpAlloc_Modern = "Static",
    [array]$PublicIpZones = @(1,2,3),     # Zone-redundant
    [string]$Lng1Name = "LocalNetworkGateway",
    [string]$Lng1PublicIp = "111.111.111.111",         # On-prem WAN public IP for Site 1
    [array]$Lng1AddressSpaces = @("172.16.20.0/24","192.168.0.0/24","192.168.20.0/24","172.16.25.0/24"),    # One or more on-prem LAN prefixes
    [string]$Lng2Name = "LocalNetworkGatewayDataCentre",
    [string]$Lng2PublicIp = "222.222.222.222",          # On-prem WAN public IP for Site 2
    [array]$Lng2AddressSpaces = @("172.16.100.0/24"),     # One or more on-prem LAN prefixes
    [string]$VpnSharedKey_Site1 = "SECRET",
    [string]$VpnSharedKey_Site2 = "SECRET",
    [string]$DNSLocation = "uksouth",
    [string]$OutboundSubnetName = 'dns-outbound-subnet',
    [string]$OutboundPrefix = '10.0.11.0/28',
    [string]$ResolverName = 'DNSPrivateEndpoint',
    [string]$FallbackResolverName = 'dnsresolver',
    [string]$OutboundEndpointName = 'outbound',
    [string]$RuleSetName          = 'ruleset',
    [string]$ForwardRuleName      = 'domain-name',
    [string]$DomainToForward      = 'domain.name.',
    [string[]]$TargetDnsIps = @('1.1.1.1','2.2.2.2'),
    [string[]]$SubnetNames = @('Windows365','AVD'),
    [string]$NatGatewayName = 'nat',
    [string]$NATPublicIpName = 'nat-pip',
    [int]$IdleTimeoutMinutes = 15,
    [string]$Mode = 'Deploy',
    [switch]$RemovePublicIpOnTearDown
)

# Authenticate using the Automation Account's Managed Identity
Connect-AzAccount -Identity | Out-Null
Set-AzContext -Subscription (Get-AzContext).Subscription

# ====== Subscription context (optional if already set) ======
Set-AzContext -Subscription $AZSubscription

Write-Host "Deploying Standard static, zone-redundant PIP + VpnGw1AZ..."

# Public IP: Standard, Static, Zone-redundant
$pip = Get-AzPublicIpAddress -Name $PublicIpName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $pip) {
    $pip = New-AzPublicIpAddress -Name $PublicIpName `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -AllocationMethod $PublicIpAlloc_Modern `
        -Sku $PublicIpSku_Modern `
        -Zone $PublicIpZones
    Write-Host "Created Standard zone-redundant Public IP '$PublicIpName'."
} else {
    Write-Host "Public IP '$PublicIpName' already exists; reusing."
}

# Get GatewaySubnet
$vnet     = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
$gwSubnet = Get-AzVirtualNetworkSubnetConfig -Name $GatewaySubnetName -VirtualNetwork $vnet

# IP config for the gateway
$ipConfig = New-AzVirtualNetworkGatewayIpConfig -Name "gwipconfig1" -SubnetId $gwSubnet.Id -PublicIpAddressId $pip.Id


# Create the VPN gateway
New-AzVirtualNetworkGateway -Name $GatewayName `
  -ResourceGroupName $ResourceGroupName `
  -Location $Location `
  -IpConfigurations $ipConfig `
  -GatewayType Vpn `
  -VpnType RouteBased `
  -GatewaySku $GatewaySku_Modern -Verbose



# Retrieve the Azure VNet Gateway
$gw = Get-AzVirtualNetworkGateway -Name $GatewayName -ResourceGroupName $ResourceGroupName -ErrorAction Stop

# --- Connection 1 (Site 1 / UniFi) ---
$lng1 = Get-AzLocalNetworkGateway -Name $Lng1Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
if (-not (Get-AzVirtualNetworkGatewayConnection -Name $Lng1Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating VPN connection for '$Lng1Name'..."
    New-AzVirtualNetworkGatewayConnection -Name $Lng1Name `
        -ResourceGroupName $ResourceGroupName `
        -VirtualNetworkGateway1 $gw `
        -LocalNetworkGateway2 $lng1 `
        -Location $Location `
        -ConnectionType IPsec `
        -SharedKey $VpnSharedKey_Site1 `
        -EnableBgp:$false | Out-Null
} else {
    Write-Host "Connection '$Lng1Name' already exists."
}

# --- Connection 2 (Site 2 / Data Centre) ---
$lng2 = Get-AzLocalNetworkGateway -Name $Lng2Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
if (-not (Get-AzVirtualNetworkGatewayConnection -Name $Lng2Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating VPN connection for '$Lng2Name'..."
    New-AzVirtualNetworkGatewayConnection -Name $Lng2Name `
        -ResourceGroupName $ResourceGroupName `
        -VirtualNetworkGateway1 $gw `
        -LocalNetworkGateway2 $lng2 `
        -Location $Location `
        -ConnectionType IPsec `
        -SharedKey $VpnSharedKey_Site2 `
        -EnableBgp:$false | Out-Null
} else {
    Write-Host "Connection '$Lng2Name' already exists."
}


# Create DNS Resolver
# ========= Get VNet =========
# Set-AzContext -Subscription $SubscriptionId
$vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
# ========= Resolver: ensure present and bound to this VNet =========
$needsNewResolver = $false
$resolver = Get-AzDnsResolver -ResourceGroupName $ResourceGroupName -Name $ResolverName -ErrorAction SilentlyContinue
if (-not $resolver) {
    $needsNewResolver = $true
} elseif (-not $resolver.VirtualNetwork -or -not $resolver.VirtualNetwork.Id -or $resolver.VirtualNetwork.Id -ne $vnet.Id) {
    # Resolver exists but is not bound to this VNet
    # Safer path: create a resolver with a different name bound to this VNet
    # (Or uncomment the Remove-AzDnsResolver below if you intend to replace it.)
    # Remove-AzDnsResolver -ResourceGroupName $ResourceGroupName -Name $ResolverName -Force
    # $needsNewResolver = $true

    # Choose a new name to avoid clobbering an in-use resolver
    $ResolverName = "hb-az-uksouth-dnsresolver"
    $needsNewResolver = $true
}
if ($needsNewResolver) {
    $resolver = New-AzDnsResolver -Name $ResolverName -ResourceGroupName $ResourceGroupName -Location $DNSLocation -VirtualNetworkId $vnet.Id
}
# ========= Outbound subnet (delegated) =========
$subnet = Get-AzVirtualNetworkSubnetConfig -Name $OutboundSubnetName -VirtualNetwork $vnet -ErrorAction SilentlyContinue
if (-not $subnet) {
    $delegation = New-AzDelegation -Name "dnsresolvers-out" -ServiceName "Microsoft.Network/dnsResolvers"
    Add-AzVirtualNetworkSubnetConfig -Name $OutboundSubnetName -VirtualNetwork $vnet -AddressPrefix $OutboundPrefix -Delegation $delegation | Out-Null
    $vnet | Set-AzVirtualNetwork | Out-Null

    # refresh
    $vnet   = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $OutboundSubnetName -VirtualNetwork $vnet
} else {
    if (-not ($subnet.Delegations | Where-Object { $_.ServiceName -eq "Microsoft.Network/dnsResolvers" })) {
        $subnet = Add-AzDelegation -Name "dnsresolvers-out" -ServiceName "Microsoft.Network/dnsResolvers" -Subnet $subnet
        Set-AzVirtualNetwork -VirtualNetwork $vnet | Out-Null
        $vnet   = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
        $subnet = Get-AzVirtualNetworkSubnetConfig -Name $OutboundSubnetName -VirtualNetwork $vnet
    }
}
# ========= Outbound endpoint =========
$outEp = Get-AzDnsResolverOutboundEndpoint -ResourceGroupName $ResourceGroupName -DnsResolverName $ResolverName -Name $OutboundEndpointName -ErrorAction SilentlyContinue
if (-not $outEp) {
    $outEp = New-AzDnsResolverOutboundEndpoint -Name $OutboundEndpointName -DnsResolverName $ResolverName -ResourceGroupName $ResourceGroupName -Location $DNSLocation -SubnetId $subnet.Id
}
# ========= Forwarding ruleset =========
$ruleSet = Get-AzDnsForwardingRuleset -ResourceGroupName $ResourceGroupName -Name $RuleSetName -ErrorAction SilentlyContinue
if (-not $ruleSet) {
    $ruleSet = New-AzDnsForwardingRuleset -Name $RuleSetName -ResourceGroupName $ResourceGroupName -Location $DNSLocation -DnsResolverOutboundEndpoint @(@{ id = $outEp.Id })
}
# ========= Forwarding rule =========
$targets = $TargetDnsIps | ForEach-Object { New-AzDnsResolverTargetDnsServerObject -IpAddress $_ -Port 53 }
$existingRule = Get-AzDnsForwardingRulesetForwardingRule -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $ForwardRuleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Update-AzDnsForwardingRulesetForwardingRule -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $ForwardRuleName -DomainName $DomainToForward -TargetDnsServer $targets -ForwardingRuleState Enabled | Out-Null
} else {
    New-AzDnsForwardingRulesetForwardingRule -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $ForwardRuleName -DomainName $DomainToForward -TargetDnsServer $targets -ForwardingRuleState Enabled | Out-Null
}
# ========= VNet link =========
$linkName = "hb-vnet-link"
$link = Get-AzDnsForwardingRulesetVirtualNetworkLink -ResourceGroupName $ResourceGroupName -DnsForwardingRulesetName $RuleSetName -Name $linkName -ErrorAction SilentlyContinue
if (-not $link) {
    New-AzDnsForwardingRulesetVirtualNetworkLink -DnsForwardingRulesetName $RuleSetName -ResourceGroupName $ResourceGroupName -Name $linkName -VirtualNetworkId $vnet.Id -Metadata @{ Owner = "HaywardBlue" } | Out-Null
}
Write-Host "Configured: $DomainToForward -> $($TargetDnsIps -join ', ') via outbound endpoint '$OutboundEndpointName' on resolver '$ResolverName'."

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
