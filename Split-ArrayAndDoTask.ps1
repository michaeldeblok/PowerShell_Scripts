$Date = (Get-Date).AddDays(-90)
$ADcomputers = Get-ADComputer -Filter 'OperatingSystem -like "*Windows 1*" -and LastLogOnDate -ge $date -and Enabled -eq $true' -Properties OperatingSystem,LastLogonDate,DnsHostName | Sort-Object DnsHostName

$counter = [pscustomobject] @{ Value = 0 }
$groupSize = 25
$groups = @()
$groups = $ADComputers | Group-Object -Property { [math]::Floor($counter.Value++ / $groupSize) }

$start = Get-Date
Write-Host $start -ForeGroundColor Cyan

$Count = 0

foreach ($group in $groups) {

    foreach ($Computer in [array]$Group.Group) {
        $null = Start-Job -ArgumentList $Computer -ScriptBlock { 

            Do-Stuff -Now -Dont -Make -Me -Wait

        }
    }

    $Count = $count + $group.group.Count
    $totalCount = $groups.Group.Count
    Write-Host "Did $($count) computers out of $($totalCount)" -ForegroundColor Yellow
    $null = Get-Job | Wait-Job | Remove-Job
}

$end = Get-Date
Write-Host $end -ForeGroundColor Cyan

$end-$start | Format-Table -AutoSize