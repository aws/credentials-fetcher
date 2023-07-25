# Using Credentials-fetcher with Kubernetes (EKS)

This is a simplified description of how to integrate Active Directory with EKS using the credentials-fetcher daemon.

Using this feature, applications running in EKS pods can use Windows Authentication to access SQL server or other services using Windows Authentication.
Applications running in EKS use AD credentials shared by the credentials-fetcher daemon running in a domain-joined instance, sharing of AD credentials is done using kubernetes.

For simplicity, the EKS cluster is created first and then Active Directory instance/server is added to one of the EKS subnets.

## Step 1. Install eksctl

`eksctl` is a command line tool for creating and managing Kubernetes clusters on Amazon EKS. For the official documentation, see https://eksctl.io/

Installation instructions to install eksctl are available [here](https://github.com/eksctl-io/eksctl/blob/main/README.md#installation)

Check eksctl version if it is installed correctly.
```bash
eksctl version
```

## Step 2. Create EKS cluster

Create a custom yaml file such as the following

````bash
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: basic-cluster
  region: us-west-1

nodeGroups:
  - name: ng-1
    instanceType: m5.large
    desiredCapacity: 2
````

Create EKS cluster using above custom yaml file.

```bash
eksctl create cluster -f cluster.yaml
```
eksctl creates a new VPC, subnets and IAM roles as well as 2 instances as mentioned in the yaml file above.

## Step 3. Setup Managed Active Directory domain using AWS console.

Click on 'Setup directory'

![Alt text](image-directory-service.png)

Select VPC and subnets created by eksctl

![Alt text](image-directory-service-choose-vpc-and-subnets.png)

## Step 4. Launch an instance and domain-join to the AD domain created above.
Domain-join can be done during instance launch as per [here](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/seamlessly_join_linux_instance.html).
Install the credentials-fetcher daemon on the domain-joined instance.


## Step 5. Modify EKS and AD security groups
Security groups for EKS and AD need to be modified so that the new domain-joined instance can access the EKS cluster and is also able to access the AD domain as before.
Make sure the EKS nodes have network connectivity to the domain, by using the nslookup command or ping.

## Step 6. Create and associate a Kubernetes secret and add a Kerberos ticket in it
### Yaml file for the secret is as follows


```yaml
%cat secret1.yaml
apiVersion: v1
data:
  password: YWJjCg==
kind: Secret
metadata:
  name: krb-ticket1
  ```

### Yaml file for the pod is as follows

Create a pod with DNS pointing to the AD domain above.
For example, `192.168.102.60` is the IP address of the AD domain `mycorp.local` in the pod.yaml below.

```yaml
% cat pod.yaml
apiVersion: v1
kind: Pod
metadata:
  namespace: default
  name: dns-example
spec:
  containers:
    - name: test
      image: nginx
  dnsPolicy: "ClusterFirstWithHostNet"
  hostNetwork: true
  dnsConfig:
    nameservers:
      - 192.168.102.60 # this is an example
    searches:
      - mycorp.local
  volumes:
    - name: secret-volume
      secret:
        secretName: krb-ticket1
```


## Step 7. Start Credentials-fetcher with EKS config file as below

```bash
% credentials_fetcher --kube-config MyEKSConfig.yaml

% cat MyEKSConfig.yaml
{
  "ServiceAccountMappings": [
    {
      "ServiceAccountName": "webapp01",
      "path_to_cred_spec_json": "contoso_webapp01.json",
      "domainless_user": "",
      "kube_context": [
        {
          "kube_context_name": "name",
          "path_to_kube_folder": "path",
          "path_to_kube_secret_yaml_file": "/home/ec2-user/credentials-fetcher/build/secret1.yaml"
        }
      ]
    },
    {
      "ServiceAccountName": "webapp02",
      "path_to_cred_spec_json": "contoso_webapp02.json",
      "domainless_user": "",
      "kube_context": [
        {
          "kube_context_name": "name",
          "path_to_kube_folder": "path",
          "path_to_kube_secret_yaml_file": "/home/ec2-user/credentials-fetcher/build/secret2.yaml"
        }
      ]
    }
  ]
}
```



##


