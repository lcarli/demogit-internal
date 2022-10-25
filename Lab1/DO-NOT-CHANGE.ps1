<#
----------------------------------------------------------------------------------
Copyright (c) Microsoft Corporation.
Licensed under the MIT license.
THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
----------------------------------------------------------------------------------
#>

<#
  .SYNOPSIS
    Migrate Policies between two tenants.
  .DESCRIPTION
    This script is used to assign Policies to the new tenant since they have the same name (management groups).
  .PARAMETER LoginServicePrincipalJson
    If set, login using the JSON credentials for the specified service principal.
  .PARAMETER ExportedPoliciesFolderName
    The name for the Root Directory. Inside this directory, all policies will be save as json files. When not set, defaults to 'ExportedPolicies'.
  .PARAMETER SubscriptionOnly
    If true, will assign only for subscriptions
  .PARAMETER ManagementGroupsOnly
    If true, will assign only for Management Groups
  .PARAMETER RunOnce
    If true, will run for the loop one time for the first subscription
  .PARAMETER SubscriptionId
    SubscriptionId to assign policies

  .EXAMPLE
    PS> .\MigratePolicies.ps1
    Migrate all policies assigning them to the new tenant
  .EXAMPLE
    PS> .\MigratePolicies.ps1 -SubscriptionOnly
    Migrate all policies assigning them to the new tenant only for the subscriptions
  .EXAMPLE
    PS> .\MigratePolicies.ps1 -ManagementGroupsOnly
    Migrate all policies assigning them to the new tenant only for the Management Groups
#>

[CmdletBinding()]
Param(
  [SecureString]$LoginServicePrincipalJson = $null,
  [string]$ExportedPoliciesFolderName = 'ExportedPolicies',
  [string]$managementGroupId = $null,
  [string]$SubscriptionId,
  [switch]$SubscriptionOnly,
  [switch]$ManagementGroupsOnly,
  [switch]$RunOnce
)

#FUNCTIONS

function LogIt ([string]$TopicName,
  [string]$message,
  [string]$ForegroundColor = "Green",
  [string]$LogToFile,
  [string]$LogToFilename = "PSLog.log") {
  #Display formatted log messages
  Write-Host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline
  Write-Host " - [" -ForegroundColor White -NoNewline
  Write-Host $TopicName -ForegroundColor Yellow -NoNewline
  Write-Host "]::" -ForegroundColor White -NoNewline
  Write-Host $message -ForegroundColor $ForegroundColor
  if ($LogToFile) {
    if ($LogToFilename -Like "PSLog.log") {} #Standard
    if (Test-Path $LogToFilename) {
      Write-Host (Get-Date).ToString() " Opening Log " $LogToFilename -ForegroundColor Green
        (Get-Date).ToString() + " - [" + $TopicName + "]::" + $message | Out-File $LogToFilename -Append
    }
    Else {
      Write-Host (Get-Date).ToString() " Creating Log " $LogToFilename -ForegroundColor Green
        (Get-Date).ToString() + " - [" + $TopicName + "]::" + $message | Out-File $LogToFilename -Append
    }
  }
}



#CODE

#Verify Module
if (Get-Module -ListAvailable -Name Az) {
  LogIt (HostName) "Az modules are installed."
} 
else {
  Install-Module Az -Force -AllowClobber
}
  
  
if ($LoginServicePrincipalJson -ne $null) {
  LogIt (HostName) "Logging in to Azure using service principal..."
  $ServicePrincipal = ($LoginServicePrincipalJson | ConvertFrom-SecureString -AsPlainText) | ConvertFrom-Json
  $Password = ConvertTo-SecureString $ServicePrincipal.password -AsPlainText -Force
  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ServicePrincipal.appId, $Password
  Connect-AzAccount -ServicePrincipal -TenantId $ServicePrincipal.tenant -Credential $Credential
}
else {
  Connect-AzAccount
}

$splitter = "\"
if ($PSVersionTable.Platform -eq "Unix") {
  $splitter = "/"
}
$dirName = $pwd.Path + $splitter + $ExportedPoliciesFolderName
$assignmentsDirectory = $dirName + $splitter + "Assignments"


#folders
Get-ChildItem -Path $assignmentsDirectory -Filter *.json -Recurse | ForEach-Object {
  $currentTargetName = $_.FullName.Split("/").Split("\")[-2]
  $content = Get-Content $_.FullName -Encoding UTF8 -Raw | ConvertFrom-Json

  #$Subscription = Get-AzSubscription -SubscriptionName 'Subscription01'
  if ($content.Properties.PolicyDefinitionId -like "*policySet*") {
    $PolicySet = Get-AzPolicySetDefinition -Name $content.Name
    New-AzPolicyAssignment -Name $content.Name -PolicySetDefinition $PolicySet -Scope "/providers/Microsoft.Management/managementgroups/$($currentTargetName)"
  }
  else {
    $Policy = Get-AzPolicyDefinition -Name $content.Name
    New-AzPolicyAssignment -Name $content.Name -PolicyDefinition $Policy -Scope "/providers/Microsoft.Management/managementgroups/$($currentTargetName)"
  }
}