
# This script does the following:
# 1) Install/Update SSM agent - without this the domain-join can fail
# 2) Create a new OU
# 3) Create a new security group
# 4) Create a new standard user account, this account's username and password needs to be stored in a secret store like AWS secrets manager.
# 5) Add members to the security group that is allowed to retrieve gMSA password
# 6) Create gMSA accounts with PrincipalsAllowedToRetrievePassword set to the security group created in 4)

# 1) Install SSM agent
Write-Output "Updating SSM agent..."
[System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
$progressPreference = 'silentlyContinue'
Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe   -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
Start-Process -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe  -ArgumentList "/S"

# To install the AD module on Windows Server, run Install-WindowsFeature RSAT-AD-PowerShell
# To install the AD module on Windows 10 version 1809 or later, run Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
# To install the AD module on older versions of Windows 10, see https://aka.ms/rsat
Write-Output "Installing Active Directory management tools..."
Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature
Install-WindowsFeature RSAT-AD-PowerShell
Install-Module CredentialSpec

$username = "admin@DOMAINNAME"
$password = "INPUTPASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
$groupAllowedToRetrievePassword = "WebAppAccounts_OU"
# This is the basedn path that needs to be in secrets manager as "distinguishedName" :  "OU=MYOU,OU=Users,OU=ActiveDirectory,DC=NETBIOS_NAME,DC=com"
$path = "OU=MYOU,OU=Users,OU=ActiveDirectory,DC=NETBIOS_NAME,DC=com"


# 2) Create OU
New-ADOrganizationalUnit -Name "MYOU" -Path "OU=Users,OU=ActiveDirectory,DC=NETBIOS_NAME,DC=com" -Credential $credential

# 3) Create the security group
try {
  New-ADGroup -Name "WebApp Authorized Accounts in OU" -SamAccountName $groupAllowedToRetrievePassword -Credential $credential -GroupScope DomainLocal  -Server DOMAINNAME
} catch {
  Write-Output "Security Group created"
}

# 4) Create a new standard user account, this account's username and password needs to be stored in a secret store like AWS secrets manager.
try {
  New-ADUser -Name "StandardUser01" -AccountPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -Enabled 1 -Credential $credential -Path $path -Server DOMAINNAME
} catch {
  Write-Output "Created StandardUser01"
}

# 5) Add members to the security group that is allowed to retrieve gMSA password
try {
  Add-ADGroupMember -Identity $groupAllowedToRetrievePassword -Members "StandardUser01" -Credential $credential -Server DOMAINNAME
  Add-ADGroupMember -Identity $groupAllowedToRetrievePassword -Members "admin" -Credential $credential -Server DOMAINNAME
} catch {
  Write-Output "Created AD Group $groupAllowedToRetrievePassword"
}

# 6) Create gMSA accounts with PrincipalsAllowedToRetrievePassword set to the security group created in 4)
$string_err = ""
for (($i = 1); $i -le NUMBER_OF_GMSA_ACCOUNTS; $i++)
{
    # Create the gMSA account
    $gmsa_account_name = "WebApp" + $i
    $gmsa_account_with_domain = $gmsa_account_name + ".DOMAINNAME"
    $gmsa_account_with_host = "host/" + $gmsa_account_name
    $gmsa_account_with_host_and_domain = $gmsa_account_with_host + ".DOMAINNAME"

    try {
       #New-ADServiceAccount -Name serviceuser1 -Path "OU=MYOU1,OU=Users,OU=ActiveDirectory,DC=ActiveDirectory1,DC=com" -Credential $credential -DNSHostname "ActiveDirectory1.com"
        New-ADServiceAccount -Name $gmsa_account_name -DnsHostName $gmsa_account_with_domain -ServicePrincipalNames $gmsa_account_with_host, $gmsa_account_with_host_and_domain -PrincipalsAllowedToRetrieveManagedPassword $groupAllowedToRetrievePassword -Path $path -Credential $credential -Server DOMAINNAME
        Write-Output "New-ADServiceAccount -Name $gmsa_account_name -DnsHostName $gmsa_account_with_domain -ServicePrincipalNames $gmsa_account_with_host, $gmsa_account_with_host_and_domain -PrincipalsAllowedToRetrieveManagedPassword $groupAllowedToRetrievePassword -Path $path -Credential $credential -Server DOMAINNAME"
    } catch {
        $string_err = $_ | Out-String
        Write-Output "Error while gMSA account creation and copy credspec to S3 bucket: " + $string_err
    }
}
