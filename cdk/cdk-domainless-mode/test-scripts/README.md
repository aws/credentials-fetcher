### Test Scripts 

#### Pre Requisites
- Ensure cdk stack is deployed to your personal account
- Create a new AL2023/Ubuntu instance in the ADStack VPC
- Install credentials-fetcher dependencies using dnf
```aiignore
dnf install -y realmd
dnf install -y oddjob
dnf install -y oddjob-mkhomedir
dnf install -y sssd
dnf install -y adcli
dnf install -y krb5-workstation
dnf install -y samba-common-tools
```
- Install the latest credentials-fetcher rpm in this instance
- Run credentials-fetcher rpm as a systemd process
```aiignore
systemctl start credentials-fetcher
systemctl status credentials-fetcher
```
- Clone credentials-fetcher repo and create a python proto file
```aiignore
git clone -b dev https://github.com/aws/credentials-fetcher.git
cd credentials-fetcher/cdk/cdk-domainless-mode/test-scripts
python3 -m venv .venv
source .venv/bin/activate
pip install grpcio-tools
python3 -m grpc_tools.protoc -I/home/ec2-user/credentials-fetcher/protos --python_out=. --grpc_python_out=. credentialsfetcher.proto
```

- To test the arn lease APIs, set the AWS environment temporary credentials
```
export AWS_ACCESS_KEY_ID = ""
export AWS_SECRET_ACCESS_KEY = ""
export AWS_SESSION_TOKEN = ""
```
