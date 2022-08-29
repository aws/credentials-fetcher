##Prerequisites:
# Create managed AD from AWS directory services and create a domain joined window instance
# To install the AD module on Windows Server, run Install-WindowsFeature RSAT-AD-PowerShell
# To install the AD module on Windows 10 version 1809 or later, run Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
# To install the AD module on older versions of Windows 10, see https://aka.ms/rsat
# Run the powershell script, replace the values of variables as required

# set up for the service account prefix and number of accounts
$service_acccount_prefix = "WebApp"
$start_of_service_account = 1
$num_of_service_accounts = 10  # number of service account to be created
[bool]$create_new_service_account = 1 # set it to 1 if need to create new service account, 0 if the existing service account need to be modified


# setup configuration for dns and spn prefix
$dns_name = "contoso.com"
$service_principal_prefix = "host/"


# hosts privileged to retrieve servive account password, name of the host machine
$access_privilege_hosts = "ec2amaz-d0t0bn$", "ec2amaz-rgwzzl$"

# Example : New-ADServiceAccount -Name "WebApp04" -DnsHostName "WebApp04.contoso.com" -ServicePrincipalNames "host/WebApp04", "host/WebApp04.contoso.com" -PrincipalsAllowedToRetrieveManagedPassword "admin","ec2amaz-t8qznk$"
# Set-ADServiceAccount -Identity "WebApp03"  -PrincipalsAllowedToRetrieveManagedPassword "WebApp01Hosts","admin","ec2amaz-t8qznk$","ec2amaz-gqebkn$","ec2amaz-uzcxba$", "ec2amaz-d0t0bn$", "ec2amaz-rgwzzl$"

for ($i=$start_of_service_account; $i -lt $start_of_service_account+$num_of_service_accounts; $i++)
{

    $service_account_name = -join("$service_acccount_prefix", "$i")
    $dns_host_name = -join("$service_account_name", ".", "$dns_name")


    $service_principal_names = -join("$service_principal_prefix", "$service_account_name"), -join("$service_principal_prefix", "$dns_host_name");
    try
    {
        if($create_new_service_account)
        {
            #Build cmd to create and run service account
            New-ADServiceAccount -Name $service_account_name -DnsHostName $dns_host_name -ServicePrincipalNames $service_principal_names -PrincipalsAllowedToRetrieveManagedPassword $access_privilege_hosts
        }
        else
        {

            Set-ADServiceAccount -Identity $service_account_name -PrincipalsAllowedToRetrieveManagedPassword $access_privilege_hosts
        }
   
     }
     Catch
     {
        # Catch any error
         Write-Host "issue with creating/updating service account or service account already created $service_account_name"
     }

}

#time for the host machine process the accounts created
Start-Sleep -Milliseconds 2000



# generate credspecs for service accounts

for ($i=$start_of_service_account; $i -lt $start_of_service_account+$num_of_service_accounts; $i++)
{
    $service_account_name = -join("$service_acccount_prefix", "$i")
    try
    {
        New-CredentialSpec -AccountName $service_account_name
    }
    catch
    {
        # Catch any error
        Write-Host "issue generating credspec/ credspec already generated for the $service_account_name"
    }
}