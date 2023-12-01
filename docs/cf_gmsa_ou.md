Active Directory administrator can create the GMSA account with any distinguished name format. 

credentials-fetcher uses the GMSA distinguished name format "CN=${GMSA_ACCOUNT_NAME},${CF_GMSA_OU},DC=example,DC=com" where ",DC=example,DC=com" is generated depending on the domain. The environment variable CF_GMSA_OU default value is "CN=Managed Service Accounts". Users should change it to match their directory format.

For example, GMSA account "BobSponge" in domain "example.com" results in GMSA distinguished name "CN=BobSponge,CN=Managed Service Accounts,DC=example,DC=com". When the user defines CF_GMSA_OU='OU=DA Managed Service Accounts,OU=DA' results in GMSA distinguished name "CN=BobSponge,OU=DA Managed Service Accounts,OU=DA,DC=example,DC=com"
