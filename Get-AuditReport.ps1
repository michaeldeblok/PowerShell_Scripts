#Requires -RunAsAdministrator
#Requires -Version 4.0
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
This script gathers the following data from the target server and outputs it into a single htm  file

.DESCRIPTION
This script gathers the following data from the target server and outputs it into a single htm  file
- General server information
- Hotfix information
- Logical Disks
- Local Administrators
- Local Members of Groups
- Firewall Profile Status
- Network Configuration
- Software
- Local Shares
- Printers
- Processes
- Processes (filtered)
- Services
- Services (filtered)
- Last logged on users
- Network Connection Information
- AD Computer
- Scheduled Tasks
- SQL Server Databases (if applicable)
- IIS Websites (if applicable)

Script must be run as an Administrator
Script must have a minimum PowerShell version of 4.0
Script must have access to the ActiveDirectory module

.NOTES
	Version History:

    3.4 - 01/01/2021 - Michael de Blok
        - Running the cmds all locally on the server vs. remote to speed up the process

    3.3 - 12/17/2020 - Michael de Blok
        - Added Last logged on users to find server/application owners
        - Added Netstat information to see number of connections to the server
        - Added an unfiltered view of running processes
        - Added a filtered view of the running processes - removes the default running processes typically seen on server 2012 R2, 2016, and 2019
        - Added a filtered view of the running services - removes the default running services typically seen on server 2012 R2, 2016, and 2019
        - Added a basic output of the server in question from Active Directory
        - Added a Members of Groups output
        - Added a filtered view of the Scheduled Tasks - removes the default scheduled tasks typically seen on server 2012 R2, 2016, and 2019
        - Added a section if a server is a SQL server to output the database path and size
        - Added a section if a server is an IIS Server to output the websites
        - Added a cmdlet to enable remote registry on the machine before doing any kind of WMIObject pull
        - Changed collecting eventlogs into a switch, since it takes a long time to gather this information and adds significant data to the htm  file
        - Rearranged order of collecting data
        - Added PowerShell Synopsis and examples
        - Minor visual tweaks

	3.2 - 4/21/2016 - Daryl Norris
		- Added Firewall status checks
		- Integrated Get-LocalGroupMembers function from Piotr Lewandowski to obtain Administrators members from local or remote systems

	3.1 - 4/21/2014 - Stephen Ostendorf
		- Added Administrators membership to report
		- OUtput folder c:\Pre_Migration_Checks\ is used for Pre Check report files

    3.0 - 1/9/2009 - Alan Renouf - http://virtu-al.net

.PARAMETER auditlist
The names of the servers. Specify a text file, with each server on a new line.
If no server list is specified the 

.PARAMETER outputPath
The folder directory of where the htm  CSV file is to be created.
If no folder is chosen it will automatically go to c:\Pre_Migration_Checks


.PARAMETER CollectEventLogs
Switch to specify the enablement of collecting event logs.
This considerable adds time to collecting data from the intended server.
This also considerable adds size to the htm  file whereas without the file could be 90KB whereas with logs could go up to 10MB if not more.

.EXAMPLE
.\Audit.ps1 -auditlist servers.txt

.EXAMPLE
.\Audit.ps1 -outputPath c:\temp

.EXAMPLE
.\Audit.ps1 -CollectEventLogs

.EXAMPLE
.\Audit.ps1 -auditlist servers.txt -outputPath c:\temp

.EXAMPLE
.\Audit.ps1 -auditlist servers.txt -outputPath c:\temp -CollectEventLogs

.EXAMPLE
.\Audit.ps1 -outputPath c:\temp -CollectEventLogs

.EXAMPLE
.\Audit.ps1 -auditlist servers.txt -CollectEventLogs

#>


param( 
	[Parameter(HelpMessage='Path to filename containing a list of computer names to be audited.')]
	[string] 
	$auditlist, 

	[Parameter(HelpMessage='Path to filename containing a list of computer names to be audited.')]
	[string] 
	$Computer, 

	[Parameter(HelpMessage='Optional: Folder path to be used as output location for reports. Default is c:\Pre_Migration_Checks.')]
	[string] 
	$outputPath="C:\Pre_Migration_Checks",

	[Parameter(HelpMessage='Optional: Enable this switch to add Event Logging to the audit')]
	[Switch] 
	$CollectEventLogs
)



Function Get-LocalGroupMembers
{
param(
[Parameter(ValuefromPipeline=$true)][array]$server = $env:computername,
$GroupName = $null
)
PROCESS {
    $finalresult = @()
    $computer = [ADSI]"WinNT://$server"

    if (!($groupName))
    {
    $Groups = $computer.psbase.Children | Where {$_.psbase.schemaClassName -eq "group"} | select -expand name
    }
    else
    {
    $groups = $groupName
    }
    $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry() | select name,objectsid
    $domain = $currentdomain.name
    $SID=$CurrentDomain.objectsid
    $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sid[0], 0)).value


    foreach ($group in $groups)
    {
    $gmembers = $null
    $LocalGroup = [ADSI]("WinNT://$server/$group,group")


    $GMembers = $LocalGroup.psbase.invoke("Members")
    $GMemberProps = @{Server="$server";LocalGroup=$group;Name="";Type="";ADSPath="";Domain="";SID=""}
    $MemberResult = @()


        if ($gmembers)
        {
        foreach ($gmember in $gmembers)
            {
            $membertable = new-object psobject -Property $GMemberProps
            $name = $gmember.GetType().InvokeMember("name",'GetProperty', $null, $gmember, $null)
            $sid = $gmember.GetType().InvokeMember("objectsid",'GetProperty', $null, $gmember, $null)
            $UserSid = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
            $class = $gmember.GetType().InvokeMember("Class",'GetProperty', $null, $gmember, $null)
            $ads = $gmember.GetType().InvokeMember("adspath",'GetProperty', $null, $gmember, $null)
            $MemberTable.name= "$name"
            $MemberTable.type= "$class"
            $MemberTable.adspath="$ads"
            $membertable.sid=$usersid.value


            if ($userSID -like "$domainsid*")
                {
                $MemberTable.domain = "$domain"
                }

            $MemberResult += $MemberTable
            }

         }
         $finalresult += $MemberResult 
    }
    $finalresult | Sort-Object domain,type,name | select LocalGroup,domain,name,type,sid
    }
}



Function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=windows-1252'>

<meta name="save" content="history">

<style type="text/css">
DIV .expando {DISPLAY: block; FONT-WEIGHT: normal; FONT-SIZE: 8pt; RIGHT: 8px; COLOR: #ffffff; FONT-FAMILY: Arial; POSITION: absolute; TEXT-DECORATION: underline}
TABLE {TABLE-LAYOUT: fixed; FONT-SIZE: 100%; WIDTH: 100%}
*{margin:0}
.dspcont { display:none; BORDER-RIGHT: #B1BABF 1px solid; BORDER-TOP: #B1BABF 1px solid; PADDING-LEFT: 16px; FONT-SIZE: 8pt;MARGIN-BOTTOM: -1px; PADDING-BOTTOM: 5px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; WIDTH: 95%; COLOR: #000000; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; BACKGROUND-COLOR: #f9f9f9}
.filler {BORDER-RIGHT: medium none; BORDER-TOP: medium none; DISPLAY: block; BACKGROUND: none transparent scroll repeat 0% 0%; MARGIN-BOTTOM: -1px; FONT: 100%/8px Tahoma; MARGIN-LEFT: 43px; BORDER-LEFT: medium none; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: medium none; POSITION: relative}
.save{behavior:url(#default#savehistory);}
.dspcont1{ display:none}
a.dsphead0 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #FFFFFF; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #CC0000}
a.dsphead1 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead2 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead1 span.dspchar{font-family:monospace;font-weight:normal;}
td {VERTICAL-ALIGN: TOP; FONT-FAMILY: Tahoma}
th {VERTICAL-ALIGN: TOP; COLOR: #CC0000; TEXT-ALIGN: left}
BODY {margin-left: 4pt} 
BODY {margin-right: 4pt} 
BODY {margin-top: 6pt} 
</style>


<script type="text/javascript">
function dsp(loc){
   if(document.getElementById){
      var foc=loc.firstChild;
      foc=loc.firstChild.innerHTML?
         loc.firstChild:
         loc.firstChild.nextSibling;
      foc.innerHTML=foc.innerHTML=='hide'?'show':'hide';
      foc=loc.parentNode.nextSibling.style?
         loc.parentNode.nextSibling:
         loc.parentNode.nextSibling.nextSibling;
      foc.style.display=foc.style.display=='block'?'none':'block';}}  

if(!document.getElementById)
   document.write('<style type="text/css">\n'+'.dspcont{display:block;}\n'+ '</style>');
</script>

</head>
<body>
<b><font face="Arial" size="5">$($Header)</font></b><hr size="8" color="#CC0000">
<font face="Arial" size="1"><b>Version 3.3 by Michael de Blok</b></font><br>
<font face="Arial" size="1">Report created on $(Get-Date)</font>
<div class="filler"></div>
<div class="filler"></div>
<div class="filler"></div>
<div class="save">
"@
Return $Report
}

Function Get-CustomHeader0 ($Title){
$Report = @"
		<h1><a class="dsphead0">$($Title)</a></h1>
	<div class="filler"></div>
"@
Return $Report
}

Function Get-CustomHeader ($Num, $Title){
$Report = @"
	<h2><a href="javascript:void(0)" class="dsphead$($Num)" onclick="dsp(this)">
	<span class="expando">show</span>$($Title)</a></h2>
	<div class="dspcont">
"@
Return $Report
}

Function Get-CustomHeaderClose{

	$Report = @"
		</DIV>
		<div class="filler"></div>
"@
Return $Report
}

Function Get-CustomHeader0Close{

	$Report = @"
</DIV>
"@
Return $Report
}

Function Get-CustomHTMLClose{

	$Report = @"
</div>

</body>
</html>
"@
Return $Report
}

Function Get-HTMLTable{
	param([array]$Content)
	$HTMLTable = $Content | ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}

Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$Heading</b></font></th>
	<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}

if ($Computer -ne "") {

$targets = $Computer

} else {}

if ($auditlist -ne ""){
	if ((Test-Path $auditlist) -eq $false)
	{
		Write-Host "Invalid audit path specified: $auditlist"
		exit
	}
	else
	{
		Write-Verbose "Starting Audit Using List: $auditlist"
		$Targets = Get-Content $auditlist
	}
}
else {}



$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"


Foreach ($Target in $Targets){
	# Remove surrounding quotes
	$Target = $Target.Replace('"', '')

	if (!(Test-Connection -Cn $Target -BufferSize 16 -Count 1 -ea 0 -quiet))
	{
		Write-Warning  "$Target is offline"
	}
	else
	{

        $number = $Targets.IndexOf($Target)
        $number = $number + 1
        $totalServers = $Targets.count

		Write-Host "Collecting details for $($target) - $($number)/$($totalServers)" -ForegroundColor Green
        $totalServers = $totalServers + 1

		try
		{
			Start-Service -InputObject $(Get-Service -Computer $Target -Name "Remote Registry") -ErrorAction SilentlyContinue
            $ComputerSystem = ""
			$ComputerSystem = Get-WmiObject -computername $Target Win32_ComputerSystem -ErrorAction "Stop"
		}
		catch
		{
			Write-Warning "Unable to connect to $Target"
		}

		if (!($ComputerSystem))
		{
			#Unable to get computersystem info
		}
		# Make sure DNS pointed to the correct computer
		# $Target may include full DNS.  ComputerSystem.Name will be short name.  Force case-insensitive compare.
		elseif ($ComputerSystem.Name -ine $Target)
		{
			Write-Output "DNS problem.  Connection attempt to $Target reached $ComputerSystem.Name instead."
		}
		else
		{
			switch ($ComputerSystem.DomainRole){
				0 { $ComputerRole = "Standalone Workstation" }
				1 { $ComputerRole = "Member Workstation" }
				2 { $ComputerRole = "Standalone Server" }
				3 { $ComputerRole = "Member Server" }
				4 { $ComputerRole = "Domain Controller" }
				5 { $ComputerRole = "Domain Controller" }
				default { $ComputerRole = "Information not available" }
			}
	
			$OperatingSystems = Get-WmiObject -computername $Target Win32_OperatingSystem
			$TimeZone = Get-WmiObject -computername $Target Win32_Timezone
			$Keyboards = Get-WmiObject -computername $Target Win32_Keyboard
			$SchedTasks = Get-WmiObject -computername $Target Win32_ScheduledJob
			$BootINI = $OperatingSystems.SystemDrive + "boot.ini"
			$RecoveryOptions = Get-WmiObject -computername $Target Win32_OSRecoveryConfiguration
	
			switch ($ComputerRole){
				"Member Workstation" { $CompType = "Computer Domain"; break }
				"Domain Controller" { $CompType = "Computer Domain"; break }
				"Member Server" { $CompType = "Computer Domain"; break }
				default { $CompType = "Computer Workgroup"; break }
			}

			$LBTime=$OperatingSystems.ConvertToDateTime($OperatingSystems.Lastbootuptime)


			Write-Output "..Regional Options"
			$ObjKeyboards = Get-WmiObject -ComputerName $Target Win32_Keyboard
			$keyboardmap = @{
			"00000402" = "BG" 
			"00000404" = "CH" 
			"00000405" = "CZ" 
			"00000406" = "DK" 
			"00000407" = "GR" 
			"00000408" = "GK" 
			"00000409" = "US" 
			"0000040A" = "SP" 
			"0000040B" = "SU" 
			"0000040C" = "FR" 
			"0000040E" = "HU" 
			"0000040F" = "IS" 
			"00000410" = "IT" 
			"00000411" = "JP" 
			"00000412" = "KO" 
			"00000413" = "NL" 
			"00000414" = "NO" 
			"00000415" = "PL" 
			"00000416" = "BR" 
			"00000418" = "RO" 
			"00000419" = "RU" 
			"0000041A" = "YU" 
			"0000041B" = "SL" 
			"0000041C" = "US" 
			"0000041D" = "SV" 
			"0000041F" = "TR" 
			"00000422" = "US" 
			"00000423" = "US" 
			"00000424" = "YU" 
			"00000425" = "ET" 
			"00000426" = "US" 
			"00000427" = "US" 
			"00000804" = "CH" 
			"00000809" = "UK" 
			"0000080A" = "LA" 
			"0000080C" = "BE" 
			"00000813" = "BE" 
			"00000816" = "PO" 
			"00000C0C" = "CF" 
			"00000C1A" = "US" 
			"00001009" = "US" 
			"0000100C" = "SF" 
			"00001809" = "US" 
			"00010402" = "US" 
			"00010405" = "CZ" 
			"00010407" = "GR" 
			"00010408" = "GK" 
			"00010409" = "DV" 
			"0001040A" = "SP" 
			"0001040E" = "HU" 
			"00010410" = "IT" 
			"00010415" = "PL" 
			"00010419" = "RU" 
			"0001041B" = "SL" 
			"0001041F" = "TR" 
			"00010426" = "US" 
			"00010C0C" = "CF" 
			"00010C1A" = "US" 
			"00020408" = "GK" 
			"00020409" = "US" 
			"00030409" = "USL" 
			"00040409" = "USR" 
			"00050408" = "GK" 
			}
			$keyb = $keyboardmap.$($ObjKeyboards.Layout)
			if (!$keyb)
			{ $keyb = "Unknown"
			}
			$MyReport = Get-CustomHTML "$Target Audit"
			$MyReport += Get-CustomHeader0  "$Target Details"
			$MyReport += Get-CustomHeader "2" "General"
				$MyReport += Get-HTMLDetail "Computer Name" ($ComputerSystem.Name)
				$MyReport += Get-HTMLDetail "Computer Role" ($ComputerRole)
				$MyReport += Get-HTMLDetail $CompType ($ComputerSystem.Domain)
				$MyReport += Get-HTMLDetail "Operating System" ($OperatingSystems.Caption)
				$MyReport += Get-HTMLDetail "Service Pack" ($OperatingSystems.CSDVersion)
				$MyReport += Get-HTMLDetail "System Root" ($OperatingSystems.SystemDrive)
				$MyReport += Get-HTMLDetail "Manufacturer" ($ComputerSystem.Manufacturer)
				$MyReport += Get-HTMLDetail "Model" ($ComputerSystem.Model)
				$MyReport += Get-HTMLDetail "Number of Processors" ($ComputerSystem.NumberOfProcessors)
				$MyReport += Get-HTMLDetail "Memory" ($ComputerSystem.TotalPhysicalMemory)
				$MyReport += Get-HTMLDetail "Registered User" ($ComputerSystem.PrimaryOwnerName)
				$MyReport += Get-HTMLDetail "Registered Organisation" ($OperatingSystems.Organization)
				$MyReport += Get-HTMLDetail "Last System Boot" ($LBTime)
				$MyReport += Get-CustomHeaderClose


				Write-Output "..Hotfix Information"
				$colQuickFixes = Get-WmiObject Win32_QuickFixEngineering
				$MyReport += Get-CustomHeader "2" "HotFixes"
					$MyReport += Get-HTMLTable ($colQuickFixes | Where {$_.HotFixID -ne "File 1" } |Select HotFixID, Description)
				$MyReport += Get-CustomHeaderClose


				Write-Output "..Logical Disks"
				$Disks = Get-WmiObject -ComputerName $Target Win32_LogicalDisk
				$MyReport += Get-CustomHeader "2" "Logical Disk Configuration"
					$LogicalDrives = @()
					Foreach ($LDrive in ($Disks | Where {$_.DriveType -eq 3})){
						$Details = "" | Select "Drive Letter", Label, "File System", "Disk Size (MB)", "Disk Free Space", "% Free Space"
						$Details."Drive Letter" = $LDrive.DeviceID
						$Details.Label = $LDrive.VolumeName
						$Details."File System" = $LDrive.FileSystem
						$Details."Disk Size (MB)" = [math]::round(($LDrive.size / 1MB))
						$Details."Disk Free Space" = [math]::round(($LDrive.FreeSpace / 1MB))
						$Details."% Free Space" = [Math]::Round(($LDrive.FreeSpace /1MB) / ($LDrive.Size / 1MB) * 100)
						$LogicalDrives += $Details
					}
					$MyReport += Get-HTMLTable ($LogicalDrives)
				$MyReport += Get-CustomHeaderClose
	<#
				Write-output "..Local Administrators"
				$GroupName="Administrators"
				$admins = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' } | ForEach-Object {[wmi]$_.PartComponent } 
				$MyReport += Get-CustomHeader "2" "Local Administrators"
				$Administrators = @()	
				Foreach ($admin in $admins) {
						
					$Details = "" | Select "Account Type", Caption, Domain, SID, "Full Name", Name
					$Details."Account Type" = $admin.AccountType
					$Details.Caption = $admin.Caption
					$Details.Domain = $admin.Domain
					$Details.SID = $admin.SID
					$Details."Full Name" = $admin.FullName
					$Details.Name = $admin.Name
						
					$Administrators += $Details
				}
				$MyReport += Get-HTMLTable ($Administrators)
				$MyReport += Get-CustomHeaderClose
	#>
				Write-output "..Local Administrators"
				$MyReport += Get-CustomHeader "2" "Local Administrators"
				$GroupName="Administrators"
				$Administrators = Get-LocalGroupMembers -server $Target -groupname $GroupName
				$MyReport += Get-HTMLTable ($Administrators)
				$MyReport += Get-CustomHeaderClose



				Write-output "..Local Members of Groups"
				$MyReport += Get-CustomHeader "2" "Local Members of Groups"
				$LUSER = Get-LocalGroupMembers -server $Target
				$MyReport += Get-HTMLTable ($LUSER)
				$MyReport += Get-CustomHeaderClose



				Write-output "..Firewall Profile Status"
				$MyReport += Get-CustomHeader "2" "Windows Firewall"
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Target)
				$DomainfirewallEnabled = $reg.OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile").GetValue("EnableFirewall")
				$StandardfirewallEnabled = $reg.OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile").GetValue("EnableFirewall")
				$PublicfirewallEnabled = $reg.OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile").GetValue("EnableFirewall")
				$MyReport += Get-HTMLDetail "Domain Firewall Profile" (@{$true="Enabled";$false="Disabled"}[$DomainfirewallEnabled -eq 1])
				$MyReport += Get-HTMLDetail "Standard Firewall Profile" (@{$true="Enabled";$false="Disabled"}[$StandardfirewallEnabled -eq 1])
				$MyReport += Get-HTMLDetail "Public Firewall Profile" (@{$true="Enabled";$false="Disabled"}[$PublicfirewallEnabled -eq 1])
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Network Configuration"
				$Adapters = Get-WmiObject -ComputerName $Target Win32_NetworkAdapterConfiguration
				$MyReport += Get-CustomHeader "2" "NIC Configuration"
					$IPInfo = @()
					Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) {
						$Details = "" | Select Description, "Physical address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, WINS
						$Details.Description = "$($Adapter.Description)"
						$Details."Physical address" = "$($Adapter.MACaddress)"
						If ($Adapter.IPAddress -ne $Null) {
						$Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
							$Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
						}
						If ($Adapter.DHCPEnabled -eq "True")	{
							$Details."DHCP Enabled" = "Yes"
						}
						Else {
							$Details."DHCP Enabled" = "No"
						}
						If ($Adapter.DNSServerSearchOrder -ne $Null)	{
							$Details.DNS =  "$($Adapter.DNSServerSearchOrder)"
						}
						$Details.WINS = "$($Adapter.WINSPrimaryServer) $($Adapter.WINSSecondaryServer)"
						$IPInfo += $Details
					}
					$MyReport += Get-HTMLTable ($IPInfo)
				$MyReport += Get-CustomHeaderClose
	
				If ((get-wmiobject -ComputerName $Target -namespace "root/cimv2" -list) | Where-Object {$_.name -match "Win32_Product"})
				{
					Write-Output "..Software"
					$MyReport += Get-CustomHeader "2" "Software"
						$MyReport += Get-HTMLTable (get-wmiobject -ComputerName $Target Win32_Product | Sort Name | select Name,Version,Vendor,InstallDate)
					$MyReport += Get-CustomHeaderClose
				}
				Else {
					Write-Output "..Software WMI class not installed"
				}
	
				Write-Output "..Local Shares"
				$Shares = Get-wmiobject -ComputerName $Target Win32_Share
				$MyReport += Get-CustomHeader "2" "Local Shares"
					$MyReport += Get-HTMLTable ($Shares | Select Name, Path, Caption)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Printers"
				$InstalledPrinters =  Get-WmiObject -ComputerName $Target Win32_Printer
				$MyReport += Get-CustomHeader "2" "Printers"
					$MyReport += Get-HTMLTable ($InstalledPrinters | Select Name, Location)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Processes"
				$Processes = Get-Process -Computer $target | Sort ProcessName
				$MyReport += Get-CustomHeader "2" "Processes"
					$MyReport += Get-HTMLTable ($Processes | Select Handles,NPM*,PM*,WS*,CPU*,Id,SI,ProcessName)
				$MyReport += Get-CustomHeaderClose


				
                Write-Output "..Processes (filtered)"
				$Processes = Get-Process -Computer $target | Sort ProcessName| where {$_.ProcessName -ne "Bootstrap" -and $_.ProcessName -ne "conhost" -and $_.ProcessName -ne "csrss" -and $_.ProcessName -ne "ctfmon" -and $_.ProcessName -ne "dllhost" -and $_.ProcessName -ne "dwm" -and $_.ProcessName -ne "explorer" -and $_.ProcessName -ne "fontdrvhost" -and $_.ProcessName -ne "Idle" -and $_.ProcessName -ne "LogonUI" -and $_.ProcessName -ne "lsass" -and $_.ProcessName -ne "mscorsvw" -and $_.ProcessName -ne "msdtc" -and $_.ProcessName -ne "MsMpEng" -and $_.ProcessName -ne "ngen" -and $_.ProcessName -ne "ngentask" -and $_.ProcessName -ne "NisSrv" -and $_.ProcessName -ne "powershell" -and $_.ProcessName -ne "rdpclip" -and $_.ProcessName -ne "rdpinput" -and $_.ProcessName -ne "Registry" -and $_.ProcessName -ne "RuntimeBroker" -and $_.ProcessName -ne "SearchUI" -and $_.ProcessName -ne "ServerManager" -and $_.ProcessName -ne "services" -and $_.ProcessName -ne "Setup" -and $_.ProcessName -ne "ShellExperienceHost" -and $_.ProcessName -ne "sihost" -and $_.ProcessName -ne "smartscreen" -and $_.ProcessName -ne "smss" -and $_.ProcessName -ne "spoolsv" -and $_.ProcessName -ne "svchost" -and $_.ProcessName -ne "System" -and $_.ProcessName -ne "taskhostw" -and $_.ProcessName -ne "VSSVC" -and $_.ProcessName -ne "wininit" -and $_.ProcessName -ne "winlogon" -and $_.ProcessName -ne "WmiApSrv" -and $_.ProcessName -ne "WmiPrvSE" -and $_.ProcessName -ne "TiWorker" -and $_.ProcessName -ne "TrustedInstaller" -and $_.ProcessName -ne "sppsvc" -and $_.ProcessName -ne "taskhostex"} | sort ProcessName 
				$MyReport += Get-CustomHeader "2" "Processes (filtered)"
					$MyReport += Get-HTMLTable ($Processes | Select Handles,NPM*,PM*,WS*,CPU*,Id,SI,ProcessName)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Services"
				$ListOfServices = Get-WmiObject -ComputerName $Target Win32_Service | Sort Name
				$MyReport += Get-CustomHeader "2" "Services"
					$Services = @()
					Foreach ($Service in $ListOfServices){
						$Details = "" | Select Name,Account,"Start Mode",State,"Expected State"
						$Details.Name = $Service.Caption
						$Details.Account = $Service.Startname
						$Details."Start Mode" = $Service.StartMode
						If ($Service.StartMode -eq "Auto")
							{
								if ($Service.State -eq "Stopped")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "Unexpected"
								}
							}
							If ($Service.StartMode -eq "Auto")
							{
								if ($Service.State -eq "Running")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "OK"
								}
							}
							If ($Service.StartMode -eq "Disabled")
							{
								If ($Service.State -eq "Running")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "Unexpected"
								}
							}
							If ($Service.StartMode -eq "Disabled")
							{
								if ($Service.State -eq "Stopped")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "OK"
								}
							}
							If ($Service.StartMode -eq "Manual")
							{
								$Details.State = $Service.State
								$Details."Expected State" = "OK"
							}
							If ($Service.State -eq "Paused")
							{
								$Details.State = $Service.State
								$Details."Expected State" = "OK"
							}
						$Services += $Details
					}
					$MyReport += Get-HTMLTable ($Services)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Services (filtered)"
				$ListOfServices = Get-WmiObject -ComputerName $Target Win32_Service | Sort Name | where {$_.Name -ne "AJRouter" -and $_.Name -ne "ALG" -and $_.Name -ne "AppIDSvc" -and $_.Name -ne "Appinfo" -and $_.Name -ne "AppMgmt" -and $_.Name -ne "AppReadiness" -and $_.Name -ne "AppVClient" -and $_.Name -ne "AppXSvc" -and $_.Name -ne "AudioEndpointBuilder" -and $_.Name -ne "Audiosrv" -and $_.Name -ne "AxInstSV" -and $_.Name -ne "BFE" -and $_.Name -ne "BITS" -and $_.Name -ne "BrokerInfrastructure" -and $_.Name -ne "BTAGService" -and $_.Name -ne "BthAvctpSvc" -and $_.Name -ne "bthserv" -and $_.Name -ne "camsvc" -and $_.Name -ne "CaptureService_2178b2" -and $_.Name -ne "CaptureService_a6d84" -and $_.Name -ne "cbdhsvc_2178b2" -and $_.Name -ne "cbdhsvc_a6d84" -and $_.Name -ne "CDPSvc" -and $_.Name -ne "CDPUserSvc_2178b2" -and $_.Name -ne "CDPUserSvc_a6d84" -and $_.Name -ne "CertPropSvc" -and $_.Name -ne "ClipSVC" -and $_.Name -ne "COMSysApp" -and $_.Name -ne "ConsentUxUserSvc_2178b2" -and $_.Name -ne "ConsentUxUserSvc_a6d84" -and $_.Name -ne "CoreMessagingRegistrar" -and $_.Name -ne "CryptSvc" -and $_.Name -ne "CscService" -and $_.Name -ne "DcomLaunch" -and $_.Name -ne "defragsvc" -and $_.Name -ne "DeviceAssociationService" -and $_.Name -ne "DeviceInstall" -and $_.Name -ne "DevicePickerUserSvc_2178b2" -and $_.Name -ne "DevicePickerUserSvc_a6d84" -and $_.Name -ne "DevicesFlowUserSvc_2178b2" -and $_.Name -ne "DevicesFlowUserSvc_a6d84" -and $_.Name -ne "DevQueryBroker" -and $_.Name -ne "Dhcp" -and $_.Name -ne "diagnosticshub.standardcollector.service" -and $_.Name -ne "DiagTrack" -and $_.Name -ne "DmEnrollmentSvc" -and $_.Name -ne "dmwappushservice" -and $_.Name -ne "Dnscache" -and $_.Name -ne "DoSvc" -and $_.Name -ne "dot3svc" -and $_.Name -ne "DPS" -and $_.Name -ne "DsmSvc" -and $_.Name -ne "DsSvc" -and $_.Name -ne "Eaphost" -and $_.Name -ne "EFS" -and $_.Name -ne "embeddedmode" -and $_.Name -ne "EntAppSvc" -and $_.Name -ne "EventLog" -and $_.Name -ne "EventSystem" -and $_.Name -ne "fdPHost" -and $_.Name -ne "FDResPub" -and $_.Name -ne "FontCache" -and $_.Name -ne "FrameServer" -and $_.Name -ne "gpsvc" -and $_.Name -ne "GraphicsPerfSvc" -and $_.Name -ne "hidserv" -and $_.Name -ne "HvHost" -and $_.Name -ne "icssvc" -and $_.Name -ne "IKEEXT" -and $_.Name -ne "InstallService" -and $_.Name -ne "iphlpsvc" -and $_.Name -ne "KeyIso" -and $_.Name -ne "KPSSVC" -and $_.Name -ne "KtmRm" -and $_.Name -ne "LanmanServer" -and $_.Name -ne "LanmanWorkstation" -and $_.Name -ne "lfsvc" -and $_.Name -ne "LicenseManager" -and $_.Name -ne "lltdsvc" -and $_.Name -ne "lmhosts" -and $_.Name -ne "LSM" -and $_.Name -ne "MapsBroker" -and $_.Name -ne "mpssvc" -and $_.Name -ne "MSDTC" -and $_.Name -ne "MSiSCSI" -and $_.Name -ne "msiserver" -and $_.Name -ne "NcaSvc" -and $_.Name -ne "NcbService" -and $_.Name -ne "Netlogon" -and $_.Name -ne "Netman" -and $_.Name -ne "netprofm" -and $_.Name -ne "NetSetupSvc" -and $_.Name -ne "NetTcpPortSharing" -and $_.Name -ne "NgcCtnrSvc" -and $_.Name -ne "NgcSvc" -and $_.Name -ne "NlaSvc" -and $_.Name -ne "nsi" -and $_.Name -ne "PcaSvc" -and $_.Name -ne "PerfHost" -and $_.Name -ne "PhoneSvc" -and $_.Name -ne "PimIndexMaintenanceSvc_2178b2" -and $_.Name -ne "PimIndexMaintenanceSvc_a6d84" -and $_.Name -ne "pla" -and $_.Name -ne "PlugPlay" -and $_.Name -ne "PolicyAgent" -and $_.Name -ne "Power" -and $_.Name -ne "PrintNotify" -and $_.Name -ne "PrintWorkflowUserSvc_2178b2" -and $_.Name -ne "PrintWorkflowUserSvc_a6d84" -and $_.Name -ne "ProfSvc" -and $_.Name -ne "PushToInstall" -and $_.Name -ne "QWAVE" -and $_.Name -ne "RasAuto" -and $_.Name -ne "RasMan" -and $_.Name -ne "RemoteAccess" -and $_.Name -ne "RemoteRegistry" -and $_.Name -ne "RmSvc" -and $_.Name -ne "RpcEptMapper" -and $_.Name -ne "RpcLocator" -and $_.Name -ne "RpcSs" -and $_.Name -ne "RSoPProv" -and $_.Name -ne "sacsvr" -and $_.Name -ne "SamSs" -and $_.Name -ne "SCardSvr" -and $_.Name -ne "ScDeviceEnum" -and $_.Name -ne "Schedule" -and $_.Name -ne "SCPolicySvc" -and $_.Name -ne "seclogon" -and $_.Name -ne "SecurityHealthService" -and $_.Name -ne "SEMgrSvc" -and $_.Name -ne "SENS" -and $_.Name -ne "Sense" -and $_.Name -ne "SensorDataService" -and $_.Name -ne "SensorService" -and $_.Name -ne "SensrSvc" -and $_.Name -ne "SessionEnv" -and $_.Name -ne "SgrmBroker" -and $_.Name -ne "SharedAccess" -and $_.Name -ne "ShellHWDetection" -and $_.Name -ne "shpamsvc" -and $_.Name -ne "smphost" -and $_.Name -ne "SNMPTRAP" -and $_.Name -ne "Spooler" -and $_.Name -ne "sppsvc" -and $_.Name -ne "SSDPSRV" -and $_.Name -ne "ssh-agent" -and $_.Name -ne "SstpSvc" -and $_.Name -ne "StateRepository" -and $_.Name -ne "stisvc" -and $_.Name -ne "StorSvc" -and $_.Name -ne "svsvc" -and $_.Name -ne "swprv" -and $_.Name -ne "SysMain" -and $_.Name -ne "SystemEventsBroker" -and $_.Name -ne "TabletInputService" -and $_.Name -ne "tapisrv" -and $_.Name -ne "TermService" -and $_.Name -ne "Themes" -and $_.Name -ne "TieringEngineService" -and $_.Name -ne "TimeBrokerSvc" -and $_.Name -ne "TokenBroker" -and $_.Name -ne "TrkWks" -and $_.Name -ne "TrustedInstaller" -and $_.Name -ne "tzautoupdate" -and $_.Name -ne "UALSVC" -and $_.Name -ne "UevAgentService" -and $_.Name -ne "UmRdpService" -and $_.Name -ne "UnistoreSvc_2178b2" -and $_.Name -ne "UnistoreSvc_a6d84" -and $_.Name -ne "upnphost" -and $_.Name -ne "UserDataSvc_2178b2" -and $_.Name -ne "UserDataSvc_a6d84" -and $_.Name -ne "UserManager" -and $_.Name -ne "UsoSvc" -and $_.Name -ne "VaultSvc" -and $_.Name -ne "vds" -and $_.Name -ne "vmicguestinterface" -and $_.Name -ne "vmicheartbeat" -and $_.Name -ne "vmickvpexchange" -and $_.Name -ne "vmicrdv" -and $_.Name -ne "vmicshutdown" -and $_.Name -ne "vmictimesync" -and $_.Name -ne "vmicvmsession" -and $_.Name -ne "vmicvss" -and $_.Name -ne "VSS" -and $_.Name -ne "W32Time" -and $_.Name -ne "WaaSMedicSvc" -and $_.Name -ne "WalletService" -and $_.Name -ne "WarpJITSvc" -and $_.Name -ne "WbioSrvc" -and $_.Name -ne "Wcmsvc" -and $_.Name -ne "WdiServiceHost" -and $_.Name -ne "WdiSystemHost" -and $_.Name -ne "WdNisSvc" -and $_.Name -ne "Wecsvc" -and $_.Name -ne "WEPHOSTSVC" -and $_.Name -ne "wercplsupport" -and $_.Name -ne "WerSvc" -and $_.Name -ne "WiaRpc" -and $_.Name -ne "WinDefend" -and $_.Name -ne "WinHttpAutoProxySvc" -and $_.Name -ne "Winmgmt" -and $_.Name -ne "WinRM" -and $_.Name -ne "wisvc" -and $_.Name -ne "wlidsvc" -and $_.Name -ne "wmiApSrv" -and $_.Name -ne "WMPNetworkSvc" -and $_.Name -ne "WPDBusEnum" -and $_.Name -ne "WpnService" -and $_.Name -ne "WpnUserService_2178b2" -and $_.Name -ne "WpnUserService_a6d84" -and $_.Name -ne "WSearch" -and $_.Name -ne "wuauserv" -and $_.Name -ne "Browser" -and $_.Name -ne "CDPUserSvc_2296e" -and $_.Name -ne "DcpSvc" -and $_.Name -ne "OneSyncSvc_2296e" -and $_.Name -ne "PimIndexMaintenanceSvc_2296e" -and $_.Name -ne "tiledatamodelsvc" -and $_.Name -ne "UI0Detect" -and $_.Name -ne "UnistoreSvc_2296e" -and $_.Name -ne "UserDataSvc_2296e" -and $_.Name -ne "WpnUserService_2296e" -and $_.Name -ne "wudfsvc" -and $_.Name -ne "XblAuthManager" -and $_.Name -ne "XblGameSave" -and $_.Name -ne "AeLookupSvc" -and $_.Name -ne "hkmsvc" -and $_.Name -ne "IEEtwCollectorService" -and $_.Name -ne "MMCSS" -and $_.Name -ne "napagent" -and $_.Name -ne "THREADORDER" -and $_.Name -ne "WcsPlugInService" -and $_.Name -ne "WSService"} | Sort Name
				$MyReport += Get-CustomHeader "2" "Services (filtered)"
					$Services = @()
					Foreach ($Service in $ListOfServices){
						$Details = "" | Select Name,Account,"Start Mode",State,"Expected State"
						$Details.Name = $Service.Caption
						$Details.Account = $Service.Startname
						$Details."Start Mode" = $Service.StartMode
						If ($Service.StartMode -eq "Auto")
							{
								if ($Service.State -eq "Stopped")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "Unexpected"
								}
							}
							If ($Service.StartMode -eq "Auto")
							{
								if ($Service.State -eq "Running")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "OK"
								}
							}
							If ($Service.StartMode -eq "Disabled")
							{
								If ($Service.State -eq "Running")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "Unexpected"
								}
							}
							If ($Service.StartMode -eq "Disabled")
							{
								if ($Service.State -eq "Stopped")
								{
									$Details.State = $Service.State
									$Details."Expected State" = "OK"
								}
							}
							If ($Service.StartMode -eq "Manual")
							{
								$Details.State = $Service.State
								$Details."Expected State" = "OK"
							}
							If ($Service.State -eq "Paused")
							{
								$Details.State = $Service.State
								$Details."Expected State" = "OK"
							}
						$Services += $Details
					}
					$MyReport += Get-HTMLTable ($Services)
				$MyReport += Get-CustomHeaderClose



				$MyReport += Get-CustomHeader "2" "Regional Settings"
					$MyReport += Get-HTMLDetail "Time Zone" ($TimeZone.Description)
					$MyReport += Get-HTMLDetail "Country Code" ($OperatingSystems.Countrycode)
					$MyReport += Get-HTMLDetail "Locale" ($OperatingSystems.Locale)
					$MyReport += Get-HTMLDetail "Operating System Language" ($OperatingSystems.OSLanguage)
					$MyReport += Get-HTMLDetail "Keyboard Layout" ($keyb)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Last logged on users"
				$LastLoggedOn = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $Target | Sort-Object -Property LastLogon -Descending
				$MyReport += Get-CustomHeader "2" "Last logged on users"
				    $MyReport += Get-HTMLTable ($LastLoggedOn  | Select-Object -Property * | Where-Object {$_.LastLogon -match "(\d{14})"} | Foreach-Object { New-Object PSObject -Property @{ Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}})
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Network Connection Information" #Invoke-Command -Computer $target -ScriptBlock { 
				$NetstatInfo = Get-NetTCPConnection | where {$_.RemoteAddress -ne "::" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1"} #}
				$MyReport += Get-CustomHeader "2" "Network Connection Information (filtered)"
				    $MyReport += Get-HTMLTable ($NetstatInfo | select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,OwningProcess)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..AD Computer Information"
				$ADComputer = Get-ADComputer $target -Properties * 
				$MyReport += Get-CustomHeader "2" "AD Computer Information"
					$MyReport += Get-HTMLTable ($ADComputer | select DNSHostName,IPv4Address,Enabled,WhenCreated,Description,OperatingSystem,OperatingSystemVersion)
				$MyReport += Get-CustomHeaderClose



				Write-Output "..Scheduled Tasks (filtered)"
				$Scheduled = Get-ScheduledTask -CimSession $target |  where {$_.TaskName -ne "User_Feed_Synchronization-{CAB6756E-F05E-44A9-A9A6-B5BAABEDBED0}" -and $_.TaskName -ne "Server Initial Configuration Task" -and $_.TaskName -ne ".NET Framework NGEN v4.0.30319" -and $_.TaskName -ne ".NET Framework NGEN v4.0.30319 64" -and $_.TaskName -ne ".NET Framework NGEN v4.0.30319 64 Critical" -and $_.TaskName -ne ".NET Framework NGEN v4.0.30319 Critical" -and $_.TaskName -ne "AD RMS Rights Policy Template Management (Automated)" -and $_.TaskName -ne "AD RMS Rights Policy Template Management (Manual)" -and $_.TaskName -ne "EDP Policy Manager" -and $_.TaskName -ne "PolicyConverter" -and $_.TaskName -ne "VerifiedPublisherCertStoreCheck" -and $_.TaskName -ne "Microsoft Compatibility Appraiser" -and $_.TaskName -ne "ProgramDataUpdater" -and $_.TaskName -ne "StartupAppTask" -and $_.TaskName -ne "appuriverifierdaily" -and $_.TaskName -ne "appuriverifierinstall" -and $_.TaskName -ne "CleanupTemporaryState" -and $_.TaskName -ne "DsSvcCleanup" -and $_.TaskName -ne "Pre-staged app cleanup" -and $_.TaskName -ne "Proxy" -and $_.TaskName -ne "BitLocker Encrypt All Drives" -and $_.TaskName -ne "BitLocker MDM policy Refresh" -and $_.TaskName -ne "UninstallDeviceTask" -and $_.TaskName -ne "BgTaskRegistrationMaintenanceTask" -and $_.TaskName -ne "AikCertEnrollTask" -and $_.TaskName -ne "CryptoPolicyTask" -and $_.TaskName -ne "KeyPreGenTask" -and $_.TaskName -ne "SystemTask" -and $_.TaskName -ne "UserTask" -and $_.TaskName -ne "UserTask-Roam" -and $_.TaskName -ne "ProactiveScan" -and $_.TaskName -ne "SyspartRepair" -and $_.TaskName -ne "License Validation" -and $_.TaskName -ne "CreateObjectTask" -and $_.TaskName -ne "Consolidator" -and $_.TaskName -ne "UsbCeip" -and $_.TaskName -ne "Data Integrity Scan" -and $_.TaskName -ne "Data Integrity Scan for Crash Recovery" -and $_.TaskName -ne "ScheduledDefrag" -and $_.TaskName -ne "Device" -and $_.TaskName -ne "Metadata Refresh" -and $_.TaskName -ne "Scheduled" -and $_.TaskName -ne "DXGIAdapterCache" -and $_.TaskName -ne "SilentCleanup" -and $_.TaskName -ne "Microsoft-Windows-DiskDiagnosticDataCollector" -and $_.TaskName -ne "Microsoft-Windows-DiskDiagnosticResolver" -and $_.TaskName -ne "Diagnostics" -and $_.TaskName -ne "StorageSense" -and $_.TaskName -ne "EDP App Launch Task" -and $_.TaskName -ne "EDP Auth Task" -and $_.TaskName -ne "EDP Inaccessible Credentials Task" -and $_.TaskName -ne "StorageCardEncryption Task" -and $_.TaskName -ne "ExploitGuard MDM policy Refresh" -and $_.TaskName -ne "Property Definition Sync" -and $_.TaskName -ne "RefreshCache" -and $_.TaskName -ne "ScanForUpdates" -and $_.TaskName -ne "ScanForUpdatesAsUser" -and $_.TaskName -ne "SmartRetry" -and $_.TaskName -ne "WakeUpAndContinueUpdates" -and $_.TaskName -ne "WakeUpAndScanForUpdates" -and $_.TaskName -ne "Installation" -and $_.TaskName -ne "Uninstallation" -and $_.TaskName -ne "TempSignedLicenseExchange" -and $_.TaskName -ne "Notifications" -and $_.TaskName -ne "WindowsActionDialog" -and $_.TaskName -ne "WinSAT" -and $_.TaskName -ne "MapsToastTask" -and $_.TaskName -ne "MapsUpdateTask" -and $_.TaskName -ne "ProcessMemoryDiagnosticEvents" -and $_.TaskName -ne "RunFullMemoryDiagnostic" -and $_.TaskName -ne "MNO Metadata Parser" -and $_.TaskName -ne "LPRemove" -and $_.TaskName -ne "SystemSoundsService" -and $_.TaskName -ne "GatherNetworkInfo" -and $_.TaskName -ne "SDN Diagnostics Task" -and $_.TaskName -ne "Background Synchronization" -and $_.TaskName -ne "Logon Synchronization" -and $_.TaskName -ne "Secure-Boot-Update" -and $_.TaskName -ne "Sqm-Tasks" -and $_.TaskName -ne "Server Manager Performance Monitor" -and $_.TaskName -ne "Device Install Group Policy" -and $_.TaskName -ne "Device Install Reboot Required" -and $_.TaskName -ne "Sysprep Generalize Drivers" -and $_.TaskName -ne "AnalyzeSystem" -and $_.TaskName -ne "LoginCheck" -and $_.TaskName -ne "Registration" -and $_.TaskName -ne "MobilityManager" -and $_.TaskName -ne "VerifyWinRE" -and $_.TaskName -ne "RegIdleBackup" -and $_.TaskName -ne "CleanupOldPerfLogs" -and $_.TaskName -ne "ServerManager" -and $_.TaskName -ne "StartComponentCleanup" -and $_.TaskName -ne "SetupCleanupTask" -and $_.TaskName -ne "Account Cleanup" -and $_.TaskName -ne "CreateObjectTask" -and $_.TaskName -ne "IndexerAutomaticMaintenance" -and $_.TaskName -ne "Collection" -and $_.TaskName -ne "Configuration" -and $_.TaskName -ne "SvcRestartTask" -and $_.TaskName -ne "SvcRestartTaskLogon" -and $_.TaskName -ne "SvcRestartTaskNetwork" -and $_.TaskName -ne "SpaceAgentTask" -and $_.TaskName -ne "SpaceManagerTask" -and $_.TaskName -ne "HeadsetButtonPress" -and $_.TaskName -ne "SpeechModelDownloadTask" -and $_.TaskName -ne "Storage Tiers Management Initialization" -and $_.TaskName -ne "Storage Tiers Optimization" -and $_.TaskName -ne "Interactive" -and $_.TaskName -ne "MsCtfMonitor" -and $_.TaskName -ne "ForceSynchronizeTime" -and $_.TaskName -ne "SynchronizeTime" -and $_.TaskName -ne "SynchronizeTimeZone" -and $_.TaskName -ne "Tpm-HASCertRetr" -and $_.TaskName -ne "Tpm-Maintenance" -and $_.TaskName -ne "Schedule Scan" -and $_.TaskName -ne "Schedule Scan Static Task" -and $_.TaskName -ne "USO_UxBroker" -and $_.TaskName -ne "UPnPHostConfig" -and $_.TaskName -ne "HiveUploadTask" -and $_.TaskName -ne "PerformRemediation" -and $_.TaskName -ne "ResolutionHost" -and $_.TaskName -ne "Windows Defender Cache Maintenance" -and $_.TaskName -ne "Windows Defender Cleanup" -and $_.TaskName -ne "Windows Defender Scheduled Scan" -and $_.TaskName -ne "Windows Defender Verification" -and $_.TaskName -ne "QueueReporting" -and $_.TaskName -ne "BfeOnServiceStartTypeChange" -and $_.TaskName -ne "UpdateLibrary" -and $_.TaskName -ne "Calibration Loader" -and $_.TaskName -ne "Scheduled Start" -and $_.TaskName -ne "CacheTask" -and $_.TaskName -ne "Automatic-Device-Join" -and $_.TaskName -ne "Recovery-Check" -and $_.TaskName -ne "Automatic App Update" -and $_.TaskName -ne "BackgroundUploadTask" -and $_.TaskName -ne "BackupTask" -and $_.TaskName -ne "EnableErrorDetailsUpdate" -and $_.TaskName -ne "ErrorDetailsUpdate" -and $_.TaskName -ne "KernelCeipTask" -and $_.TaskName -ne "Maintenance Install" -and $_.TaskName -ne "NetworkStateChangeTask" -and $_.TaskName -ne "Plug and Play Cleanup" -and $_.TaskName -ne "Policy Install" -and $_.TaskName -ne "Reboot" -and $_.TaskName -ne "Refresh Settings" -and $_.TaskName -ne "Resume On Boot" -and $_.TaskName -ne "sih" -and $_.TaskName -ne "sihboot" -and $_.TaskName -ne "SmartScreenSpecific" -and $_.TaskName -ne "USO_UxBroker_Display" -and $_.TaskName -ne "USO_UxBroker_ReadyToReboot" -and $_.TaskName -ne "XblGameSaveTask" -and $_.TaskName -ne "XblGameSaveTaskLogon" -and $_.TaskName -ne "AitAgent" -and $_.TaskName -ne "AUFirmwareInstall" -and $_.TaskName -ne "AUScheduledInstall" -and $_.TaskName -ne "AUSessionConnect" -and $_.TaskName -ne "Automatic-Workplace-Join" -and $_.TaskName -ne "BindingWorkItemQueueHandler" -and $_.TaskName -ne "Daily Collector" -and $_.TaskName -ne "Idle Maintenance" -and $_.TaskName -ne "Maintenance Configurator" -and $_.TaskName -ne "Manual Maintenance" -and $_.TaskName -ne "RacTask" -and $_.TaskName -ne "Regular Maintenance" -and $_.TaskName -ne "ServerCeipAssistant" -and $_.TaskName -ne "ServerRoleCollector-RunOnce" -and $_.TaskName -ne "SQM data sender" -and $_.TaskName -ne "WSTask" -and $_.TaskName -ne "MusUx_UpdateInterval"} | Select TaskPath,TaskName,State | Sort TaskName 
				$MyReport += Get-CustomHeader "2" "Scheduled Tasks (filtered)"
					$MyReport += Get-HTMLTable ($Scheduled | Select TaskPath,TaskName,State)
				$MyReport += Get-CustomHeaderClose



                $SqlServerThere = Get-Service -ComputerName $target | where {$_.DisplayName -like "SQL Server (*"}
                if ($SqlServerThere -ne $null) {
                    Write-Output "..SQL Server Databases"
	                $SQLServer = Invoke-Command -ComputerName $target -ScriptBlock { Get-PSDrive -PSProvider "FileSystem" | % {Get-ChildItem $_.Root *.MDF -Recurse -ErrorAction "SilentlyContinue" } }
	                $MyReport += Get-CustomHeader "2" "SQL Server Databases"
		                $MyReport += Get-HTMLTable ($SQLServer | Sort Length -Descending | Select Name,@{Name="Size in MB";Expression={ "{0:N0}" -f ($_.Length / 1MB) }},LastAccessTime,LastWriteTime,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }},Directory )
	                $MyReport += Get-CustomHeaderClose
                } else {}




                $WWWServiceThere = Get-Service -ComputerName $target | where {$_.Name -eq "W3SVC"}
                if ($WWWServiceThere -ne $null) {
            	    Write-Output "..IIS Websites"
				    $IISWebsite = Invoke-Command -ComputerName $target -ScriptBlock { Get-IISSite }
				    $MyReport += Get-CustomHeader "2" "IIS Websites"
					    $MyReport += Get-HTMLTable ($IISWebsite | select Name,ID,State,Physical,Path,Bindings)
				    $MyReport += Get-CustomHeaderClose
                } else {}



<#
    if ($CollectEventLogs -ne ""){
				Write-Output "..Event Log Settings"
				$LogFiles = Get-WmiObject -ComputerName $Target Win32_NTEventLogFile
				$MyReport += Get-CustomHeader "2" "Event Logs"
					$MyReport += Get-CustomHeader "2" "Event Log Settings"
					$LogSettings = @()
					Foreach ($Log in $LogFiles){
						$Details = "" | Select "Log Name", "Overwrite Outdated Records", "Maximum Size (KB)", "Current Size (KB)"
						$Details."Log Name" = $Log.LogFileName
						If ($Log.OverWriteOutdated -lt 0)
							{
								$Details."Overwrite Outdated Records" = "Never"
							}
						if ($Log.OverWriteOutdated -eq 0)
						{
							$Details."Overwrite Outdated Records" = "As needed"
						}
						Else
						{
							$Details."Overwrite Outdated Records" = "After $($Log.OverWriteOutdated) days"
						}
						$MaxFileSize = ($Log.MaxFileSize) / 1024
						$FileSize = ($Log.FileSize) / 1024
				
						$Details."Maximum Size (KB)" = $MaxFileSize
						$Details."Current Size (KB)" = $FileSize
						$LogSettings += $Details
					}




					$MyReport += Get-HTMLTable ($LogSettings)
					$MyReport += Get-CustomHeaderClose
					Write-Output "..Event Log Errors"
					$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
					$LoggedErrors = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Error' and TimeWritten >='" + $WmidtQueryDT + "'")
					$MyReport += Get-CustomHeader "2" "ERROR Entries"
						$MyReport += Get-HTMLTable ($LoggedErrors | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
					$MyReport += Get-CustomHeaderClose
					Write-Output "..Event Log Warnings"
					$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
					$LoggedWarning = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Warning' and TimeWritten >='" + $WmidtQueryDT + "'")
					$MyReport += Get-CustomHeader "2" "WARNING Entries"
						$MyReport += Get-HTMLTable ($LoggedWarning | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
					$MyReport += Get-CustomHeaderClose
				$MyReport += Get-CustomHeaderClose


} else {}
#>


				$MyReport += Get-CustomHeaderClose
			$MyReport += Get-CustomHeader0Close
			$MyReport += Get-CustomHTMLClose
			$MyReport += Get-CustomHTMLClose
			#Write-Host ...Creating Pre-Migration Directory
			#New-Item -Path c:\Pre_Migration_Checks\ -ItemType directory | Out-Null
			if (!(Test-Path -Path $outputPath)) {
				Write-Host  "...Creating Pre-Migration Directory $outputPath"
				New-Item -ItemType directory -Path $outputPath | Out-Null
			}

			$Date = Get-Date
			$Filename = $outputPath + "\" + $Target + ".htm"
			$MyReport | out-file -encoding ASCII -filepath $Filename
			Write "Audit saved as $Filename"
		}
	}
}
