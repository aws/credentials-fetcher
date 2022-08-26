# Credentials Fetcher
Credentials fetcher is installable rpm which runs on Linux distributions, it
works similar to that of CCG.exe on windows which is responsible for 
authentication for gMSA accounts with Active directory to
orchestrate the kerberos tickets specific to group managed service 
accounts (gMSA) to services running on a server farm, containers or on 
systems behind Network Load Balancer.

## Link to the Blog
The information on running this software is provided in the blog
[Credentials Fetcher documentation](_placeholder_for_the_blog_).

### On the Linux distributions
On the [Amazon Linux 2022](_https__:__//aws.amazon.com/amazon-linux-ami/_) and [Fedora 36](_https://alt.fedoraproject.org/cloud/_), we provide an installable RPM which can be used via
`sudo yum install credentials-fetcher && sudo systemctl start credentials-fetcher`. This is the recommended way to run it in this 
environment. For the other linux distributions pull the source code build, 
install rpm  and run 'sudo systemctl start credentials-fetcher' to start the service

## Developing Credentials Fetcher
### Prereq
We require the following:
* Active Directory server
* Domain joined Linux instances or workspaces
* gMSA service account - Follow instructions provided to create service accounts - https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts

#### create credentialspec associated to service account:
* Create a domain joined windows instance
* Install powershell module - "Install-Module CredentialSpec"
* New-CredentialSpec -AccountName WebApp01 // Replace 'WebApp01' with your own gMSA
* You will find the credentialspec in the directory 
  'C:\Program Data\Docker\Credentialspecs\WebApp01_CredSpec.json'

### Getting started developing
#### Single commands
To start a local dev environment from scratch.
```
* Clone the Git repository.
* cd CredentialsFetcher && mkdir build
* cd build && cmake .. && make -j
* Run the binary (./credentials-fetcher) to start the gRPC server
```
#### Testing
To communicate with the daemon over gRPC we need to install grpc cli
'sudo yum install grpc-cli'

##### AddkerberosLease endpoint:
```
Invoke the AddkerberosLease endpoint with the credentialsspec input as shown:
grpc_cli call {unix_domain_socket} AddKerberosLease "credspec_contents: '{credentialspec}'"

Sample:
grpc_cli call unix:/var/credentials-fetcher/socket/credentials_fetcher.sock
AddKerberosLease "credspec_contents: '{\"CmsPlugins\":[\"ActiveDirectory\"],\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\",
\"MachineAccountName\":\"WebApp01\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\",\"DnsTreeName\":\"contoso.com\",
\"DnsName\":\"contoso.com\",\"NetBiosName\":\"contoso\"},\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"WebApp01\",\"Scope\":\"contoso.com\"}
,{\"Name\":\"WebApp01\",\"Scope\":\"contoso\"}]}}'"

* Response:
  lease_id - unique identifier associated to the request
  created_kerberos_file_paths - Paths associated to the Kerberos tickets created corresponding to the gMSA accounts
```

##### DeletekerberosLease endpoint:
```
Invoke the Delete kerberosLease endpoint with lease id input as shown:
grpc_cli call {unix_domain_socket} DeleteKerberosLease "lease_id: '{lease_id}'"

Sample:
grpc_cli call unix:/var/credentials-fetcher/socket/credentials_fetcher.sock DeleteKerberosLease "lease_id: '${response_lease_id_from_add_kerberos_lease}'"

* Response: 
    lease_id - unique identifier associated to the request
    deleted_kerberos_file_paths - Paths associated to the Kerberos tickets deleted corresponding to the gMSA accounts

```

### logging
Get the log information about the request/response to the server and daemon failures
```
journalctl -u credentials-fetcher
```

#### Default environment variables
| Environment Key             |  Examples values                     | Description                                                                                  |
|:----------------------------|--------------------------------------|:---------------------------------------------------------------------------------------------|
| `CF_KRB_DIR`                |  '/var/credentials-fetcher/krbdir'   | *(Default)* Dir path for storing the kerberos tickets                                        |
| `CF_UNIX_DOMAIN_SOCKET_DIR` |  '/var/credentials-fetcher/socket'   | *(Default)* Dir path for the domain socker for gRPC communication 'credentials_fetcher.sock' |
| `CF_LOGGING_DIR`            |  '/var/credentials-fetcher/logging'  | *(Default)* Dir Path for log |                                                                |
| `CF_TEST_DOMAIN_NAME`       |  'contoso.com'                       | Test domain name                                                                             |
| `CF_TEST_GMSA_ACCOUNT`      |  'webapp01'                          | Test gMSA account name                                                                       |


## Building and Running from Source
Running the Credentials Fetcher outside of Linux distributions is not
supported.

## Contributing
Contributions and feedback are welcome! Proposals and pull requests will be considered and responded to. For more
information, see the [CONTRIBUTING.md](https://github.
com/aws/credentials-fetcher/blob/master/CONTRIBUTING.md) file.
If you have a bug/and issue around the behavior of the credentials-fetcher, 
please open it here.

Amazon Web Services does not currently provide support for modified copies of this software.

## Security disclosures
If you think you’ve found a potential security issue, please do not post it in the Issues.  Instead, please follow the instructions [here](_https__:__//aws.amazon.com/security/vulnerability-reporting/_) or [email AWS security directly](_mailto:aws-security@amazon.com_).

## License
The Credentials Fetcher is licensed under the Apache 2.0 License.
See [LICENSE](_./__LICENSE_) and [NOTICE](_./__NOTICE_) for more information.