####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## In order to recreate an OU structure from another AD infrastructure run the following in the source domain
## Get-ADOrganizationalUnit -Filter * -Properties * | Export-Clixml ADOrganizationalUnit.xml
##
#######################################




$OUs = Import-Clixml ADOrganizationalUnit.xml

foreach ($OU in $OUs){

 Write-Host "Doing OU $($OU.Name)" -ForegroundColor Cyan

 $name = $OU.Name
 $DN = $OU.DistinguishedName

 $path = $DN -replace "OU=$name,"

 New-ADOrganizationalUnit -Name $name -Path $path -Description $OU.Description -DisplayName $OU.DisplayName -City $OU.City -Country $OU.Country -PostalCode $OU.PostalCode -State $OU.State -ProtectedFromAccidentalDeletion:$true -StreetAddress $OU.StreetAddress

 }