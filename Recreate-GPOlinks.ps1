####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## In order to recreate GPO Links from another AD infrastructure run the following in the source domain
## 
## Get-GPO -All | Export-CliXml GPOs.xml
## 
## The assumption is that you have already recreated the OU structure with the Recreate-OUStructure.ps1 script
## You must replace DC=DOMAIN,DC=LOCAL with the values from your domain
##
#######################################

$OUs = Import-Clixml .\ADOrganizationalUnit.xml
$GPOs = Import-Clixml .\GPOs.xml

foreach ($OU in $OUs) {

    Write-Host "Doing OU $($OU.CanonicalName)" -ForegroundColor Cyan

    $policies = $OU.LinkedGroupPolicyObjects
    $policies = $policies -replace "cn={",""
    $policies = $policies -replace "},cn=policies,cn=system,DC=DOMAIN,DC=LOCAL",""


        foreach ($policy in $policies) {

            $OldGPO = ($GPOs | Where-Object {$_.Id -eq $policy}).DisplayName

            Write-Host "..Adding $($OldGPO)"

            $null = New-GPLink -Name $OldGPO -LinkEnabled Yes -Target $OU.DistinguishedName
        }
}