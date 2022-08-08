#!/bin/bash


for((i=1; i <= 3 ; i++))
do   
     service_account_name="WebApp${i}"
     domain_name="contoso"

     add_krb_msg="#######  Adding kerberos lease #######"
     echo ${add_krb_msg}

     add_kerberos_lease=$(grpc_cli call unix:/var/opt/credentials-fetcher/socket/credentials_fetcher.sock AddKerberosLease "credspec_contents: '{\"CmsPlugins\":[\"ActiveDirectory\"],\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\",\"MachineAccountName\":\"${service_account_name}\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\",\"DnsTreeName\":\"${domain_name}.com\",\"DnsName\":\"${domain_name}.com\",\"NetBiosName\":\"${domain_name}\"},\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"${service_account_name}\",\"Scope\":\"${domain_name}.com\"},{\"Name\":\"${service_account_name}\",\"Scope\":\"${domain_name}\"}]}}'")

   echo "Add kerberos lease response: ${add_kerberos_lease}"  
   add_kerberos_lease_id=$(echo "${add_kerberos_lease}" | grep  'lease_id' | cut -f2 -d: | tr -d ' ' | tr -d '\n')

   echo "Added kerberos ticket for lease_id: ${add_kerberos_lease_id}"

   delete_krb_msg="#######  Deleting kerberos lease #######"
   echo ${delete_krb_msg}
   delete_kerberos_lease=$(grpc_cli call unix:/var/opt/credentials-fetcher/socket/credentials_fetcher.sock DeleteKerberosLease "lease_id: '${add_kerberos_lease_id}'")

   echo "Delete kerberos tickets corresponding to lease: ${delete_kerberos_lease}"

done
