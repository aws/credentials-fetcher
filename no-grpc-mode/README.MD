"No gRPC Mode" is intended to be used for this scenario:
* Neeeds to run on Amazon Linux 2 which does not have packages available for gRPC
* EKS host not ECS
* Need to run via command line and not configured via gRPC api calls
* Containers do not need access to kerbos tickets

#compile no_grpc_mode on AmazonLinux2

```
  sudo yum install git -y
  sudo yum install gcc10-c++ -y
  sudo mv /usr/bin/gcc /usr/bin/gcc-7.3
  sudo ln -s /usr/bin/gcc10-cc /usr/bin/gcc
  sudo mv /usr/bin/g++ /usr/bin/g++-7.3
  ln -s /usr/bin/gcc10-c++ /usr/bin/g++
  sudo ln -s /usr/bin/gcc10-c++ /usr/bin/g++
  sudo mv /usr/bin/c++ /usr/bin/c++-7.3
  ln -s /usr/bin/gcc10-c++ /usr/bin/c++
  sudo ln -s /usr/bin/gcc10-c++ /usr/bin/c++
  sudo yum install openssl-devel -y
  sudo yum install openssl-devel -y
```
  
  need a newer version of CMake so compile from source
``` 
 git clone https://github.com/Kitware/CMake.git -b release \
    && cd CMake && ./configure && make -j8 &&  pwd && sudo make install
```
  
  #install DotNet 6  
```
  sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm  
  sudo yum install aspnetcore-runtime-6.0 -y
  sudo yum install dotnet-sdk-6.0 -y
  cd ..
```  
  #Install packages need by Credentials-Fetcher
``` 
 sudo yum install glib* -y
  sudo yum install jsoncpp-devel jsoncpp -y
  sudo yum install systemd-devel -y
 ```

  #build Credentials-Fetcher
```
  cd no-grpc-mode/
  mkdir build
  cd build
   
  cmake ../
  make -j 4
```

#Copy helper app to /usr/sbin
  sudo cp credentials_fetcher_utf16_private.exe /usr/sbin/
  sudo cp credentials_fetcher_utf16_private.runtimeconfig.json /usr/sbin/
 ```
 
  #install prereqs to run
```
  sudo yum install realmd -y
  sudo yum install krb5-workstation -y
  sudo yum install openldap -y
  sudo yum install openldap-clients -y
  sudo yum install cyrus-sasl-gssapi -y
```  

#set environment variables need to run in CLI mode 
```
  export CF_CRED_SPEC_FILE=/home/ec2-user/credentials-fetcher/no-grpc-mode/build/credspec.json  
  #todo:make sure EC2 Instance Profile has permissions to AWS Secrets Manager
  export AWS_REGION=us-east-1
```

#run it in domainless mode by specific the AWS SecretsManger secret
#Replace gmsa-plugin-input with your AWS SecretsManager secret name.

```
 ./credentials-fetcherd --aws_sm_secret_name gmsa-plugin-input
```

#You should see output similar to this
```
[root@ip-10-0-61-81 build]#  ./credentials-fetcherd --aws_sm_secret_name gmsa-plugin-input
Option selected for domainless operation, AWS secrets manager secret-name = gmsa-plugin-input
krb_files_dir = /var/credentials-fetcher/krbdir
cred_file = /home/ec2-user/credentials-fetcher/no-grpc-mode/build/credspec.json (lease id: credspec)
logging_dir = /var/credentials-fetcher/logging
unix_socket_dir = /var/credentials-fetcher/socket
Using existing cache: persistent:0:0
Using principal: eks-portable-ident@EXAMPLE.COM
prompt at 0x970ea702, 0x400,  '��
prompt at 0x970ea702, 0x400,  '��
Authenticated to Kerberos v5
ldapsearch -H ldap://DC2.example.com -b 'CN=gmsaeks,CN=Managed Service Accounts,DC=example,DC=com' -s sub  "(objectClass=msDs-GroupManagedServiceAccount)"  msDS-ManagedPassword
SASL/GSSAPI authentication started
SASL username: eks-portable-ident@EXAMPLE.COM
SASL SSF: 256
SASL data security layer installed.
dotnet /usr/sbin/credentials_fetcher_utf16_private.exe | kinit  -c /var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc -V 'gmsaeks$'@EXAMPLE.COM
Using specified cache: /var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc
Using principal: gmsaeks$@EXAMPLE.COM
Password for gmsaeks$@EXAMPLE.COM: 
Authenticated to Kerberos v5
kinit return value = 0
gMSA ticket is at /var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc
Thread 0: top of stack near 0x7fc7f18c7c88; argv_string=krb_ticket_refresh_thread

```


