# Description: This script sets security settings for one or more Azure Repositories for one or more teams in an Azure DevOps organization and project.
# Author: Alejandra Guillen

# Parameters:
# - repoStartsWith: The name of the repository to filter by. If not specified, all repositories will be listed.

# Prerequisites:
# - Install the Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

# How to use:
# - Run the script and follow the prompts to select an organization, project, team(s), and security actions for ALLOW and DENY.
# - The script will list all repositories in the selected project and prompt you to select one or more repositories.
# - The script will then set the security settings for the selected repositories for the selected team(s).

# Example:
# - Run the script with the following command:
#   ./set-repos-security.ps1

# Example with parameter:
# - Run the script with the following command to filter repositories by name:
#   ./set-repos-security.ps1 -repoStartsWith "MyRepo"

param(
    [string] $repoStartsWith = $null,
    [string] $token= $null
)

$ErrorActionPreference = "Stop"

# Retrieve the access token
$token = Read-Host "`n`nEnter the Pat Token"

if ($token)
{

# Define Headers for the REST API request
$base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
$headers = @{Authorization=("Basic {0}" -f $base64AuthInfo)}


# Get the current user's profile
$currentProfile = Invoke-RestMethod -Uri "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.0" -Headers $headers -Method Get 


# Get all organizations current user is a member of
$allOrganizations = (Invoke-RestMethod -Uri "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$($currentProfile.id)&api-version=7.0" -Headers $headers -Method Get).value

if ($allOrganizations)
{
# Prompt user to select an organization
Write-Host "`n`nSelect an organization:"
for ($i = 0; $i -lt $allOrganizations.Length; $i++) {
    Write-Host "$($i+1): $($allOrganizations[$i].accountName) - $($allOrganizations[$i].accountUri) "
}
[int]$orgIndex = Read-Host "`nEnter the number of the organization" -ErrorAction Stop
$organization = $allOrganizations[$orgIndex - 1]

$orgBaseUrl = $organization.accountUri.Replace("vssps.", "")
Write-Host -ForegroundColor Cyan "Organization: $($organization.accountName) - $orgBaseUrl"


# Retrieve Projects for the selected organization
$projects = (Invoke-RestMethod -Uri "$($orgBaseUrl)_apis/projects?api-version=7.0" -Headers $headers -Method Get).value
# Prompt user to select a project
Write-Host "`n`nSelect a project:"
for ($i = 0; $i -lt $projects.Length; $i++) {
    Write-Host "$($i+1): $($projects[$i].name) - $($projects[$i].id) "
}
[int]$projectIndex = Read-Host "`nEnter the number of the project" -ErrorAction Stop
$project = $projects[$projectIndex - 1]
$projectName = $project.name

# Retreive Azure Repositories for the selected organization
$repos = (Invoke-RestMethod -Uri "$($orgBaseUrl)$($project.id)/_apis/git/repositories?api-version=7.2-preview.1" -Headers $headers -Method Get).value
$repos | format-table -Property name, webUrl -AutoSize

#if ([string]::IsNullOrEmpty($repoStartsWith)) {
    #$repos = $repos | Where-Object { $_.name -like "$repoStartsWith*" }
#} 
$repoStartsWith = Read-Host 'Enter the Repo Prefix'
if ($repoStartsWith)
{
     $repos = $repos | Where-Object { $_.name -like "$repoStartsWith*" }
}

$repos | format-table -Property name, webUrl -AutoSize

# Retrieve Groups
$orgBaseUrl1 = $organization.accountUri.Replace("app.", "")
#$teams = (Invoke-RestMethod -Uri "$($orgBaseUrl)_apis/projects/$($project.id)/teams?`$expandIdentity=true&api-version=7.2-preview.3_apis/projects/$($project.id)/teams?`$expandIdentity=true&api-version=7.2-preview.3" -Headers $headers -Method Get).value
$groups = (Invoke-RestMethod -Uri "$($orgBaseUrl1)_apis/graph/groups?api-version=5.0-preview.1" -Headers $headers -Method Get).value
$groups = $groups | Sort-Object -Property principalName -Descending
#$teams | format-table -Property principalName -AutoSize
#$teams = $teams | Where-Object { $_.principalName -like "[$projectName]*" }
#$teams = $teams.value.diaplayName
# Prompt user to select one or more groups
Write-Host "`n`nSelect one or more group:"
for ($i = 0; $i -lt $groups.Length; $i++) {
    Write-Host "$($i+1): $($groups[$i].principalName) - $($groups[$i].id) "
}
[array]$groupIndexes = (Read-Host "Enter the number(s) of the group(s) comma separated" -ErrorAction Stop).Trim().Split(",")
$selectedGroups = $groups | Where-Object { $groupIndexes -contains ($groups.IndexOf($_) + 1) }



$securityNamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" # This is the Security Namespace for 'Git Repositories' - See: https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops
$securityNamespace = (Invoke-RestMethod -Uri "$($orgBaseUrl)_apis/securitynamespaces/$($securityNamespaceId)?api-version=7.2-preview.1" -Headers $headers -Method Get).value
#$securityNamespace.actions | format-table -Property bit, name, displayName -AutoSize 

# Prompt user to select one or more security actions
Write-Host "`n`nSelect one or more security actions for ALLOW:"
for ($i = 0; $i -lt $securityNamespace.actions.Length; $i++) {
    Write-Host "$($i+1): $($securityNamespace.actions[$i].name) - $($securityNamespace.actions[$i].displayName)"
}
[array]$securityActions = (Read-Host "Enter the number(s) of the security action(s) comma separated" -ErrorAction Stop).Trim().Split(",")
$allowActions = $securityNamespace.actions | Where-Object { $securityActions -contains ($securityNamespace.actions.IndexOf($_) + 1) }

Write-Host "`n`nSelect one or more security actions for DENY:"
for ($i = 0; $i -lt $securityNamespace.actions.Length; $i++) {
    Write-Host "$($i+1): $($securityNamespace.actions[$i].name) - $($securityNamespace.actions[$i].displayName) "
}
[array]$securityActions = (Read-Host "Enter the number(s) of the security action(s) comma separated" -ErrorAction Stop).Trim().Split(",")
$denyActions = $securityNamespace.actions | Where-Object { $securityActions -contains ($securityNamespace.actions.IndexOf($_) + 1) }

foreach ($repo in $repos) {
    # Set Access Control Entries (ACEs) on a Git repository.
    # Set the repository token format from doc: https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops
    $repoToken = "repoV2/$($repo.project.id)/$($repo.id)"
    
    $body = @{
        token                = $repoToken
        merge                = $true
        accessControlEntries = @()
    }

    foreach ($group in $selectedGroups) {

        Write-Host "`nUpdating security settings for $($repo.name) for group $($group.name)..."
        # Write-Host " - Current security settings for $($repo.name) for team $($team.name):"
        # $currentTeamACLs = (Invoke-RestMethod -Uri "$($orgBaseUrl)_apis/accesscontrollists/$($securityNamespaceId)?token=$($repoToken)&descriptors=$($team.identity.descriptor)&includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1" -Headers $headers -Method Get).value
        
        # $dictionary = @{}
        # $currentTeamACLs.acesDictionary | Get-Member -MemberType NoteProperty | ForEach-Object {
        #     $dictionary[$_.Name] = $currentTeamACLs.acesDictionary.$($_.Name)
        # }
        # $dictionary.Values | Format-Table -Property * -AutoSize
        
        $body.accessControlEntries += @{
            descriptor = $group.descriptor
            allow      = $allowActions | ForEach-Object { $_.bit } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            deny       = $denyActions | ForEach-Object { $_.bit } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        }

        # Set the access control entries for the repository
        $aces = Invoke-WebRequest -Uri "$($orgBaseUrl)_apis/accesscontrolentries/$($securityNamespaceId)?api-version=7.2-preview.1" -Headers $headers -Method Post -Body ($body | ConvertTo-Json) -ContentType "application/json" 

        Write-Host " - New security settings for $($repo.name) for group $($group.name) updated successfully:"
        # $currentTeamACLs = (Invoke-RestMethod -Uri "$($orgBaseUrl)_apis/accesscontrollists/$($securityNamespaceId)?token=$($repoToken)&descriptors=$($team.identity.descriptor)&includeExtendedInfo=true&recurse=true&api-version=7.2-preview.1" -Headers $headers -Method Get).value
        
        # $dictionary = @{}
        # $currentTeamACLs.acesDictionary | Get-Member -MemberType NoteProperty | ForEach-Object {
        #     $dictionary[$_.Name] = $currentTeamACLs.acesDictionary.$($_.Name)
        # }
        # $dictionary.Values | Format-Table -Property * -AutoSize
        
        # Clear the accessControlEntries array for the next team
        $body.accessControlEntries = @() 
    }
}

Write-Host "`n`nSecurity settings updated successfully for the selected repositories and groups." -ForegroundColor Green
}
else
{
    Write-host "`n`nUser not presnt in Azure DevOps Organization"
}
}

