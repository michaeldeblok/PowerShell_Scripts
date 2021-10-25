####################################### 
##
## Created by Michael de Blok 
## Version 0.01
##
## In order to recreate AD Users from another AD infrastructure run the following in the source domain
##
## Get-ADUser -Filter * -Properties * | Export-Clixml ADuser.xml
##
#######################################

Function GenerateStrongPassword ([Parameter(Mandatory=$true)][int]$PasswordLength)
{
    Add-Type -AssemblyName System.Web
    $PassComplexCheck = $false
    do {
        $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLength,1)
    If ( 
        ($newPassword -cmatch "[A-Z\p{Lu}\s]") `
        -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
        -and ($newPassword -match "[\d]") `
        -and ($newPassword -match "[^\w]")
        )
        {
            $PassComplexCheck=$True
        }
    } While ($PassComplexCheck -eq $false)
    return $newPassword
}

$adusers = Import-Clixml .\ADuser.xml

$adusers = $adusers | Sort-Object Name

foreach ($user in $adusers) {

    Write-Host "Doing user $($user.Name)" -ForegroundColor Cyan

    $password = ConvertTo-SecureString (GenerateStrongPassword (16)) -AsPlainText -Force

     $DN = $User.DistinguishedName
     $path = $DN -replace "^.*?,"
     
    New-ADUser -AccountPassword $password -ChangePasswordAtLogon $false -City $user.City -Company $user.Company -Country $user.Country -Department $user.Department -DisplayName $user.DisplayName -Description $user.Description -Division $user.Division -EmailAddress $user.EmailAddress -EmployeeID $user.EmployeeID -EmployeeNumber $user.EmployeeNumber -Enabled $true -GivenName $user.GivenName -Initials $user.Initials -MobilePhone $user.MobilePhone -Name $user.Name -Office $user.Office -OfficePhone $user.OfficePhone -Organization $user.Organization -OtherName $user.OtherName -SamAccountName $user.SamAccountName -Path $path -POBox $user.POBox -PostalCode $user.PostalCode -State $user.State -StreetAddress $user.StreetAddress -Surname $user.Surname -Title $user.Title -UserPrincipalName $user.UserPrincipalName
}