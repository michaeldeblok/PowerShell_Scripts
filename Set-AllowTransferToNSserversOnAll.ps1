####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## This Script sets the Primary Dns Server Zone setting to 'Only to the servers listed in the name server tab' from whatever setting it was before
## In this particular use case there were BIND servers transferring the zone from Windows DNS, but kept losing it's zone because Windows DNS kept reverting its setting to 'only the following servers' effectively disallowing any server not in that list
## The script is run as a job to speed up the process and run the commands in parallel vs. serial on each server
##
#######################################

Write-Host 'Provide Domain Administrator credentials to allow connection to the Domain Controllers' -ForegroundColor Cyan
$cred = Get-Credential

Write-Host '..Enumerating Domain Controllers'
$LogonServer = $env:LOGONSERVER -replace '\\',''
$DCs = (Get-ADDomainController -Filter * -Server $LogonServer -Credential $cred | Where-Object {$_.IsReadOnly -ne $true} | Sort-Object HostName).HostName
$ClosestDC = $DCs | Where-Object {$_ -like "*$LogonServer*"}

Write-Host '..Enumerating DNS Zones'
Invoke-Command -ComputerName $ClosestDC -Credential $cred -ScriptBlock {Get-DnsServerZone | Where-Object {$_.ZoneType -eq "Primary"} | Select-Object ZoneName,ZoneType,IsAutoCreated,IsDsIntegrated,IsReverseLookupZone,IsSigned | Format-Table -AutoSize} -AsJob | Wait-Job | Receive-Job

Write-Host 'Which DNS zone do you want to make the setting change on? ' -NoNewline -ForegroundColor Cyan
$DnsZone = Read-Host

$DCs | ForEach-Object { 
    Write-Host '..Changing setting on server ' -NoNewline
    Write-Host $_ -ForegroundColor Green
    Invoke-Command -ComputerName $_ -Credential $cred -ScriptBlock {Set-DnsServerPrimaryZone -Name $using:DnsZone -SecureSecondaries TransferToZoneNameServer} -AsJob 
} | Wait-Job | Receive-Job

Write-Host ''
Write-Host 'Do you want to run the script continuously for an hour every minute? [Y/N] ' -ForegroundColor Yellow -NoNewline
$Answer = Read-Host

if ($Answer -like 'y*') {
    1..60 | ForEach-Object { 
        $DCs | ForEach-Object { 
            Write-Host '..Changing setting on server ' -NoNewline
            Write-Host $_ -ForegroundColor Green
            Invoke-Command -ComputerName $_ -Credential $cred -ScriptBlock {Set-DnsServerPrimaryZone -Name $using:DnsZone -SecureSecondaries TransferToZoneNameServer} -AsJob } | Wait-Job | Receive-Job
            Write-Host 'Sleeping for 1 minute' -ForegroundColor Yellow
            Start-Sleep 60 
        }
} else {}