$Date = (Get-Date).AddDays(-30)
$ADcomputers = Get-ADComputer -Filter 'OperatingSystem -like "*Windows 1*" -and LastLogOnDate -ge $date -and Enabled -eq $true' -Properties OperatingSystem,LastLogonDate,DnsHostName | Sort-Object DnsHostName


$ping = $ADcomputers.DnsHostName | Test-NetConnection
$alive = ($ping | where {$_.PingSucceeded -eq $true}).ComputerName
$SessionOption = New-PSSessionOption -MaxConnectionRetryCount 1
New-PSSession -ComputerName ($alive | Where-Object {$_ -notlike "*doco*"}) -SessionOption $SessionOption
$session = Get-PSSession
Invoke-Command -Session $session -ScriptBlock {




}


$Computers = @()
for ($i = 0; $i -lt $ADcomputers.count; $i += 10) {
   $Computers += ,@($ADcomputers[$i..($i+9)]);
}

foreach ($computer in $Computers[0..99999]) {

    Invoke-Command -AsJob -ComputerName $computer.DnsHostname -ScriptBlock {hostname} -ErrorAction SilentlyContinue
}




<#
$bigList = 1..1000

$counter = [pscustomobject] @{ Value = 0 }
$groupSize = 100

$groups = $bigList | Group-Object -Property { [math]::Floor($counter.Value++ / $groupSize) }
#>