# AzureAutomation
Azure automations for lab environments
Initial PowerShell scripts create/destroy an Azure Virtual Network Gateway, DNS Private resolver, and NAT Gateway.

This is designed to create temporary resources for testing that can be easily created/destroyed to save cost, useful for example with Visual Studio subscriptions.

Pre-requisites:
Azure subscription
Resource Group
Two public IP addresses
Local Network Gateways
Automation Account with required permissions

Disclaimer(s):
- Is it pretty? no.
- Could it be better? Yes, I'll keep working on it.
- Did I use ChatGPT to help? Yes, don't think it did all of it, there were some shocking hallucinations, and some of the code, although it works, I'm convinced it's not great.
- You don't use native modules in all cases, why? Automation Accounts, for whatever reason didn't like some PowerShell modules.  It works fine in the cloud shell, fails in the Automation Account.  I just got it to work!
- Why are there variables in there that you declare, but don't use?  There was a lot of trial and error and I need to clean it up.
