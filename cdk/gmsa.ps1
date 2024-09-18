Write-Output "Installing Active Directory management tools..."

# Install SSM agent
[System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
$progressPreference = 'silentlyContinue'
Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe   -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
Start-Process -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe  -ArgumentList "/S"

Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature
Install-WindowsFeature RSAT-AD-PowerShell
Install-Module CredentialSpec

$username = "admin@DOMAINNAME"
$password = "INPUTPASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

# To install the AD module on Windows Server, run Install-WindowsFeature RSAT-AD-PowerShell
# To install the AD module on Windows 10 version 1809 or later, run Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
# To install the AD module on older versions of Windows 10, see https://aka.ms/rsat

try {
  # Create the security group
  New-ADGroup -Name "WebApp01 Authorized Accounts" -SamAccountName "WebApp01Accounts" -GroupScope DomainLocal -Credential $credential -Server DOMAINNAME
} catch {
  Write-Output "Security Group created"
}

$string_err = ""
for (($i = 1); $i -le NUMBER_OF_GMSA_ACCOUNTS; $i++)
{
    # Create the gMSA account
    $gmsa_account_name = "WebApp" + $i
    $gmsa_account_with_domain = $gmsa_account_name + ".DOMAINNAME"
    $gmsa_account_with_host = "host/" + $gmsa_account_name
    $gmsa_account_with_host_and_domain = $gmsa_account_with_host + ".DOMAINNAME"

    try {
        Write-Output 'New-ADServiceAccount -Name $gmsa_account_name -DnsHostName $gmsa_account_with_domain -ServicePrincipalNames $gmsa_account_with_host, $gmsa_account_with_host_and_domain -PrincipalsAllowedToRetrieveManagedPassword "WebApp01Accounts" -Credential $credential -Server DomainName'
        New-ADServiceAccount -Name $gmsa_account_name -DnsHostName $gmsa_account_with_domain -ServicePrincipalNames $gmsa_account_with_host, $gmsa_account_with_host_and_domain -PrincipalsAllowedToRetrieveManagedPassword "WebApp01Accounts" -Credential $credential -Server DOMAINNAME
    } catch {
        $string_err = $_ | Out-String
        Write-Output "Error while gMSA account creation and copy credspec to S3 bucket: " + $string_err
    }

}

# Create the standard user account. This account information needs to be stored in a secret store and will be retrieved by the ccg.exe hosted plug-in to retrieve the gMSA password. Replace 'StandardUser01' and 'p@ssw0rd' with a unique username and password. We recommend using a random, long, machine-generated password.

try {
  New-ADUser -Name "StandardUser01" -AccountPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -Enabled 1 -Credential $credential -Server DOMAINNAME
} catch {
  Write-Output "Created StandardUser01"
}

try {
  # Add your container hosts to the security group
  Add-ADGroupMember -Identity "WebApp01Accounts" -Members "StandardUser01" -Credential $credential -Server DOMAINNAME
} catch {
  Write-Output "Created AD Group Member"
}