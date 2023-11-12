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
```
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

#build the RPM for distribution

```
sudo yum install -y rpmdevtools rpmlint -y
rpmdev-setuptree

sudo ln -s /usr/local/bin/cmake /usr/bin/cmake3


cp ~/credentials-fetcher/no-grpc-mode/package/credentials-fetcher.spec ~/rpmbuild/SPECS
mkdir ~/tmp

cp -r credentials-fetcher/no-grpc-mode/ ~/tmp

cd ~/tmp && mv no-grpc-mode credentials-fetcher-v.1.2.0
tar cvfz v.1.2.0.tar.gz credentials-fetcher-v.1.2.0
cp v.1.2.0.tar.gz ~/rpmbuild/SOURCES/

rpmbuild -ba ~/rpmbuild/SPECS/credentials-fetcher.spec 

```


# Using Credentials-Fetcher with EKS/SMB


### Scenario

If you have EKS pods operating on Amazon Linux 2 and require access to SMB file shares using Kerberos authentication, even when the EKS worker nodes are not part of the Windows Active Directory domain. The use of Kerberos authentication is crucial to guarantee SMB encryption-in-transit for compliance purposes.

### Solution

Implement the SMB CSI Driver with Kerberos authentication settings to enable the mounting of SMB shares onto the pods. Employ the Credentials-Fetcher to generate and update Kerberos tickets as needed.

### References

* https://github.com/kubernetes-csi/csi-driver-smb
* https://aws.amazon.com/blogs/containers/using-amazon-fsx-for-windows-file-server-as-persistent-storage-on-amazon-eks/
* https://aws.amazon.com/blogs/opensource/aws-now-supports-credentials-fetcher-for-gmsa-on-amazon-linux-2023/
* 

### Prerequisites:

* Microsoft Active Directory
* gMSA Account in AD
* credspec.json generated from the gMSA Account
* FSx NetApp with an SMB File share on a Volume configured with NTFS permissions style
* SMB File share permissions assigned for read/write to the gMSA account
* Amazon EKS Cluster
* Amazon EKS Worker Node operating on Amazon Linux 2



### Install SMB CSI Driver

```
curl -skSL https://raw.githubusercontent.com/kubernetes-csi/csi-driver-smb/v1.13.0/deploy/install-driver.sh | bash -s v1.13.0 --
```

```

mkdir -p /etc/krb5.conf.d/
echo "[libdefaults]
#SMB CSI Driver should look for krbcc files output by Credentials-Fetcher, 
#not the placeholder ticket stored in Kubernetes secret 
default_ccache_name = FILE:/var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc" > /etc/krb5.conf.d/ccache.conf

```



### Create SMBCreds Secret

```
#This kerberos ticket cache won't actually be used
#just use an "empty" file
#cifs/smb mount will actually find anduse gMSA ticket in
#/var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc
#created by credentials-fetcher service

echo "empty" > /tmp/emptycache
export EMPTYCACHEFILE=/tmp/emptycache
EMPTYCACHE=$(base64 -w 0 $EMPTYCACHEFILE)

kubectl create secret generic smbcreds --from-literal krb5cc_0=$EMPTYCACHE


```

### Apply Persistent Volume (PV)

```
---
apiVersion: v1
kind: PersistentVolume
metadata:
  annotations:
    pv.kubernetes.io/provisioned-by: smb.csi.k8s.io
  name: pv-smb
spec:
  capacity:
    storage: 100Gi
  accessModes:
    - ReadWriteMany
  persistentVolumeReclaimPolicy: Retain
  storageClassName: smb
  mountOptions:
    - sec=krb5
    - cruid=0
    - dir_mode=0777
    - file_mode=0777
    - uid=1000   
    - gid=1000
    - noperm
    - mfsymlinks
    - cache=strict
    - noserverino  # required to prevent data corruption
  csi:
    driver: smb.csi.k8s.io
    readOnly: false
    # volumeHandle format: {smb-server-address}#{sub-dir-name}#{share-name}
    # make sure this value is unique for every share in the cluster
    volumeHandle: smb-server.default.svc.cluster.local/share##
    volumeAttributes:
      source: "//svm1.example.com/smb1"
    nodeStageSecretRef:
      name: smbcreds
      namespace: default
```

```
kubectl apply -f pv-smb.yaml
```



### Apply Persistent Volume Claim (PVC)

```
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: pvc-smb
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 10Gi
  volumeName: pv-smb
  storageClassName: smb
```

```
kubectl apply -f pvc-smb.yaml
```



### Install Credentials-Fetcher Amazon Linux 2 RPM

```
#add Microsoft repo so .Net 6 dependency can be installed
sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm  

yum install credentials-fetcher-1.2.0-3.amzn2.x86_64.rpm -y

```

### Set Environment Variables for  [credentials-fetcher.service](https://github.com/awsjohns/credentials-fetcher/blob/34777570e5c49d93258038d6d4c6d8bef33d306b/scripts/systemd/credentials-fetcher.service)

* Edit /usr/lib/systemd/system/credentials-fetcher.service

```
#we need to set so credentials-fetcher doesn't use whats in /etc/krb5.conf.d for the user ticket.
#/var/credentials-fetcher/krbdir/credspec/gmsaeks/krb5cc is for the gMSA ticket 
Environment="KRB5CCNAME=/var/credentials-fetcher/krbdir/krb5cc"
#add secret parameter
ExecStart=/usr/sbin/credentials-fetcherd --aws_sm_secret_name gmsa-plugin-input
```

### Start daemon service

```
#start the service
sudo systemctl start credentials-fetcher.service

#view the logs
sudo journalctl -u credentials-fetcher
```



### Test with EKS Pod that reads/writes to SMB file share


create pv-smb-pod.yaml with below YAML:

```
apiVersion: v1
kind: Pod
metadata:
  name: pod-smb-reader-writer
spec:
  volumes:
  - name: smb-pv-storage
    persistentVolumeClaim:
      claimName: pvc-smb
  containers:
  - image: busybox
    name: smb-writer
    command: ["/bin/sh","-c","while true; do echo $(date) Logging data >> /output/output.log; echo wrote; sleep 5; done"]
    volumeMounts:
    - name: smb-pv-storage
      mountPath: /output
  - image: busybox
    name: smb-reader
    command: ['/bin/sh', '-c', 'tail -f /input/output.log']
    volumeMounts:
    - name: smb-pv-storage
      mountPath: /input
```

### Deploy the EKS pod



```
kubectl apply -f pv-smb-pod.yaml
```

```

# kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
pod-smb-reader-writer   2/2     Running   0          22s
```



