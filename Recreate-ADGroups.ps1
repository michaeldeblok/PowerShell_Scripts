####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## In order to recreate AD Groups from another AD infrastructure run the following in the source domain
##
## Get-ADGroup -Filter * -Properties * | Export-Clixml ADGroup.xml
##
#######################################

$ADGroups = Import-Clixml .\ADGroup.xml

$ADGroups = $ADGroups | Sort-Object Name

foreach ($group in $ADgroups) {

    Write-Host "Doing user $($group.Name)" -ForegroundColor Cyan

    $DN = $group.DistinguishedName
    $path = $DN -replace "^.*?,"

    New-ADGroup -Description $group.Description -DisplayName $group.DisplayName -Name $group.Name -Path $path -SamAccountName $group.SamAccountName -GroupCategory $group.GroupCategory -GroupScope $group.GroupScope
    if (!($group.Members.Count -le 1)) {Add-ADGroupMember -Identity $group.Name -Members $group.Members} else {}

}