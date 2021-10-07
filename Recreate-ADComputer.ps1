####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## In order to recreate an AD Users from another AD infrastructure run the following in the source domain
## Get-Computer -Filter * -Properties * | Export-Clixml ADComputer.xml
##
#######################################



$adcomputers = Import-Clixml .\ADcomputer.xml

$adcomputers = $adcomputers | Sort Name

foreach ($computer in $adcomputers) {

    Write-Host "Doing user $($Computer.Name)" -ForegroundColor Cyan

    $name = $Computer.Name
    $DN = $Computer.DistinguishedName
    #$path = $DN -replace "CN=$name,"
    $path = $DN -replace "^.*?,"

    New-ADComputer -Description $computer.Description -DisplayName $computer.DisplayName -DNSHostName $computer.DNSHostName -Enabled $true -Name $computer.Name -OperatingSystem $computer.OperatingSystem -Path $path -SAMAccountName $computer.SamAccountName -UserPrincipalName $computer.UserPrincipalName

}