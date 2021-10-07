




$OUs = Import-Clixml .\ADOrganizationalUnit.xml
$GPOs = Import-Clixml .\GPOs.xml


foreach ($ou in $ous) {



Write-Host "Doing OU $($OU.CanonicalName)" -ForegroundColor Cyan

    $policies = $ou.LinkedGroupPolicyObjects
    $policies = $policies -replace "cn={",""
    $policies = $policies -replace "},cn=policies,cn=system,DC=dropbox,DC=internal",""


        foreach ($policy in $policies) {

            $OldGPO = ($GPOs | where {$_.Id -eq $policy}).DisplayName

            Write-Host "..Adding $($OldGPO)"

            $null = New-GPLink -Name $OldGPO -LinkEnabled Yes -Target $ou.DistinguishedName


        }




}