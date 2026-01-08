# CredentialsFetcherV2

## Overview

This package is the Golang refactor of [credentials-fetcher](https://github.com/aws/credentials-fetcher).

## Getting Started

### Prerequisites

The following dependencies are needed on the instance

```
dnf install openldap-clients krb5-workstation sssd 
```

For domain joined mode, the following additional dependencies are needed to domain join the instance to the realm
```
dnf install realmd oddjob oddjob-mkhomedir adcli
```

* Brazil workspace environment
* AWS CLI and IAM user configured with appropriate permissions for deploying CDK and running Hydra Tests
* Node.js and npm installed
* Python 3.9+ installed

### Development and Testing

It is recommended to develop on AL (ex: cloud desktop). To test any changes, an EC2 instance with Active Directory setup is a requirement.

## Create Brazil Workspace

```
brazil ws create --root CredentialsFetcherV2 --vs CredentialsFetcherV2/development
cd CredentialsFetcherV2

# Download all required packages
brazil ws use -p CredentialsFetcherV2
brazil ws use -p CredentialsFetcherV2CDK
brazil ws use -p CredentialsFetcherV2Tests
```

## 2. Local Package Build

### Build All Packages

From the workspace root:

```
# Clean and build all packages
brazil-recursive-cmd --allPackages "brazil-build clean && brazil-build release"
```

## 3. CDK Infrastructure Deployment

### Navigate to CDK Package

```
cd src/CredentialsFetcherV2CDK
```

### Personal AWS Account Setup

Set up deployment to your personal AWS account:

```
# Set your personal AWS account ID
export DEV_ACCOUNT_ID={account-id}

# Bootstrap CDK (first time only)
bb cdk bootstrap aws://{account-id}/{region}

# Deploy S3 stack first
bb cdk deploy CredentialsFetcherV2-s3-stack-dev --require-approval never
```

### Create Test RPM using RPM build script 

#### TODO: Fill this out with open source RPM build instructions

### Upload RPM to S3 Bucket

**IMPORTANT**: Upload the `Credentials-Fetcher` RPM now before deploying remaining stacks:

* Grab the latest RPM from the Pipeline Account Artifacts [Bucket](https://tiny.amazon.com/14korydui/IsenLink)
    * Make Sure to Sort by Last Modified

```
# Get your deployment prefix from CDK stack names
PREFIX=$(bb cdk list | grep "Infra-dev-" | sed 's/CredentialsFetcherV2-Infra-dev-//')

# Get the S3 bucket name from SSM parameter
BUCKET_NAME=$(aws ssm get-parameter --name "/$PREFIX/rpm-artifacts-bucket-name" --query "Parameter.Value" --output text --region {region})

# Upload the RPM built using the rpm_build script
aws s3 cp {rpm-path} s3://$BUCKET_NAME/
```
### Deploy Remaining Stacks

After uploading the RPM, deploy the remaining infrastructure:


```
# Deploy all remaining stacks (takes 45-90 minutes)
bb cdk deploy --all --require-approval never
```


**Variables to Replace:**

* `{account-id}`: Your personal AWS account ID
* `{region}`: Target AWS region (recommended: us-west-2)
* `{rpm-path}`: Path to CredentialsFetcher RPM file provided by CredentialsFetcher Team

## 4. Run Integration Test Suite

Run comprehensive integration tests on AWS Fargate:

```
bb clean && bb release && hydra run \
  --package-name CredentialsFetcherV2Tests-1.0 \
  --invocation-role {role} \
  --run-definition '{
    "SchemaVersion": "1.0",
    "SchemaType": "HydraCustom",
    "HydraParameters": {
      "Runtime": "python3.12",
      "EntryPoint": "fargate/entry_point_python_default.sh",
      "Handler": "hydra_test_platform_pytest.fargate_handler.handler",
      "ComputeEngine": "Fargate",
      "Timeout": 7200
    },
    "HandlerParameters": {
      "PythonTestPackage": "hydra_tests"
    },
    "EnvironmentVariables": {
      "Region": "{region}",
      "Stage": "{stage}",
      "NamePrefix": "{prefix}"
    }
  }' \
  --region {region}
```


**Variables to Replace:**

* `{role}`: Your AWS IAM role for Hydra execution (e.g., HydraInvocationRole)
* `{region}`: Target AWS region (recommended: us-west-2)
* `{stage}`: Environment stage
* `{prefix}`: Your deployment prefix



### Individual Test Execution

**Set Environment Variables**

```
export Region={region}            # e.g., us-east-2
export Stage={stage}              # e.g., dev, alpha
export NamePrefix={prefix}        # Your deployment prefix
```

**Run tests:**

```
# Navigate to test package
cd src/CredentialsFetcherV2Tests

# Optional: View active tests (configured by conftest.py)
python -m pytest --collect-only

# Run any test file
python -m pytest src/hydra_tests/pathTo/{test_file}.py -v -s

# Specific examples:
# RPM Size Test
python -m pytest src/hydra_tests/fargate/test_credentials_fetcher_size_monitor.py -v -s

# Domain Joined Renewal Test
python -m pytest src/hydra_tests/renewal/test_dj_credentials_renewal.py -v -s
```

## 5. Testing GRPC APIs Directly

For manual testing of individual GRPC APIs on the machine with CredentialsFetcher running.


### Setup Active Directory

Before running individual API tests, setup the Active Directory environment using SSM documents:

**Note**:

* Run these commands from your local machine or AWS console, not on the EC2 instances, as they don't have SSM permissions.
* For each SSM Command goto AWS Console → Systems Manager → Run Command → Command History, and **double check the Command Output** to confirm that the Documents ran successfully. Commands are configured to **fail silently.**

```
# Step 1: Create standard user
aws ssm send-command \
  --instance-ids {instance-id} \
  --document-name "{prefix}-CreateStandardUser" \
  --parameters "EnvironmentId=hydra-{region}"
  --region {region}
  
# Step 2: Create AD group
aws ssm send-command \
  --instance-ids {instance-id} \
  --document-name "{prefix}-CreateADGroup" \
  --parameters "EnvironmentId=hydra-{region},HostNames={hostnames}"
  --region {region}

# Step 3: Create OU and gMSA accounts
aws ssm send-command \
  --instance-ids {instance-id} \
  --document-name "{prefix}-CreateOuAndGmsaAccounts" \
  --parameters "NumberOfGmsaAccounts=10,EnvironmentId=hydra-{region}"
  --region {region}
  
# Step 4: Configure firewall and SQL
aws ssm send-command \
  --instance-ids {instance-id} \
  --document-name "{prefix}-ConfigureFirewallAndSQL" \
  --parameters "NumberOfGmsaAccounts=10,EnvironmentId=hydra-{region}"
  --region {region}
```

**Variables to Replace:**

* `{instance-id}`: Windows instance ID from your deployment (in EC2 console, named `{prefix}-ConfigurationInstance`)
* `{prefix}`: Your deployment prefix
* `{region}`: AWS region (recommended: us-west-2)
* `{hostnames}`: Single string containing comma-separated domain joined instance hostnames (can be found by running `hostname` command in domain-joined instances, e.g., `ip-10-0-3-212.ec2.internal,ip-10-0-0-50.ec2.internal`)

This initializes the Active Directory environment required for the individual API tests.


#### Verify Changes Propogated to AD

1. In AWS Console, go to Systems Manager → Fleet Manager
2. Click on the Instance ID of the Windows Instance
3. Click on Node Actions → Connect → Connect with Remote Desktop
4. Retrieve Username and Password of AD Secret from Secrets Manager and use them to login to the Instance
5. Open `Active Directory Users and Computers`
6. Expand the `Contoso` domain and verify that the AD Group, `StandardUser01` user, and gMSA accounts exist and are setup correctly


### Confirm CredentialsFetcher is Running

Verify that CredentialsFetcher is installed and running on all instances:


```
# Check if CredentialsFetcher is installed. If installed, move on to the next section
rpm -qa | grep credentials-fetcher

# If not installed, download and install the RPM
# First, get the RPM from S3 bucket
aws s3 cp s3://$BUCKET_NAME/{rpm-filename} ./

# Second, Install CredentialsFetcher RPM
sudo dnf install -y ./{rpm-filename}

# Third, Start the service
sudo systemctl daemon-reload
sudo systemctl enable credentials-fetcher.service
sudo systemctl start credentials-fetcher.service
sudo systemctl status credentials-fetcher.service

# Fourth Restart ECS (only if on an ECS instance)
sudo systemctl restart ecs

# Check logs if needed
sudo journalctl -u credentials-fetcher.service -f
```

**Note**: Replace `{rpm-filename}` with the actual RPM filename created above


### Download Test Assets from S3 to test EC2 Instance

The CDK creates a credspec S3 bucket with test assets. Find the bucket name:

```
# List S3 buckets to find the credspec bucket
aws s3 ls | grep tuxnet.credspec

# Download all test assets from S3 (all files are in the root)
aws s3 sync s3://tuxnet.credspec.{stage}.{prefix}/ ./test-assets/
```


This downloads:

* Test scripts: `.py` files (add_kerberos_lease_template.py, etc.)
* Proto file: `credentialsfetcher.proto`
* Credspecs: `.json` files (contoso_WebApp01_dj.json, contoso_WebApp01_ndj.json)


Replace `{stage}` with your deployment stage (e.g., `dev`) and `{prefix}` with your unique deployment prefix.


### Setup Python Environment on the EC2

Create a virtual environment and install dependencies:

```
# Navigate to test-assets directory
cd test-assets

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install grpcio grpcio-tools
```

### Generate Python GRPC Files

Create the required `.pb2` files from the proto definition:

```
# Generate Python GRPC files
python -m grpc_tools.protoc --proto_path=test-assets --python_out=test-assets --grpc_python_out=test-assets test-assets/credentialsfetcher.proto
```

This creates:

* `test-assets/credentialsfetcher_pb2.py` - Message classes
* `test-assets/credentialsfetcher_pb2_grpc.py` - Service stub classes

#### Test Script Breakdown

**Domain Joined APIs:**

* `add_kerberos_lease_template.py` - Tests `AddKerberosLease` API
* `delete_kerberos_lease_template.py` - Tests `DeleteKerberosLease` API
* `add_kerberos_arn_lease_template.py` - Tests `AddKerberosArnLease` API
* `renew_kerberos_arn_lease_template.py` - Tests `RenewKerberosArnLease` API

**Non-Domain Joined APIs:**

* `add_non_domain_joined_kerberos_lease_template.py` - Tests `AddNonDomainJoinedKerberosLease` API
* `renew_non_domain_joined_kerberos_lease_template.py` - Tests `RenewNonDomainJoinedKerberosLease` API

**Load Testing:**

* `stress_test_template.py` - Stress tests multiple API calls

### Running Individual Tests

```
# Navigate to test-assets directory (if not already there)
cd test-assets

# Activate virtual environment
source venv/bin/activate

# Replace placeholders in test scripts with actual values:
# - {CREDSPEC_PLACEHOLDER} with credspec content from .json files
# - {USERNAME_PLACEHOLDER} with domain username
# - {PASSWORD_PLACEHOLDER} with domain password
# - {DOMAIN_PLACEHOLDER} with domain name

# Example: Test AddKerberosLease API
python add_kerberos_lease_template.py

# Example: Test Non-Domain Joined lease
python add_non_domain_joined_kerberos_lease_template.py
```

### Credential Specifications

Use the downloaded credspec files:

* `contoso_WebApp01_dj.json` - Domain joined credential spec
* `contoso_WebApp01_ndj.json` - Non-domain joined credential spec

Replace template placeholders with your environment-specific values before using in test scripts.

## 6. Viewing Logs

### Tail Live Logs

```
sudo journalctl -u credentials-fetcher -f
```

### View Logs from Timestamp

```
sudo journalctl -u credentials-fetcher --since "2025-01-08 21:00:00"
```

## 7. Testing Local Changes

**Note:**

* You **must** build your changes on a Cloud Desktop, otherwise the `credentials-fetcher` binary will fail to run

### Build your Changes

```
cd src/CredentialsFetcherV2
brazil-build clean && brazil-build
```

### **Upload Build Artifacts to S3 Bucket**

* You’ll need a scratch S3 Bucket to transfer the `credentials-fetcher` test artifacts to your S3 Bucket

```
aws s3 cp ./build/bin/credentials-fetcher s3://{bucket-name}
aws s3 cp ./configuration/bin/credentials-fetcher.service s3://{bucket-name}
aws s3 cp ./configuration/conf/credentials-fetcher.conf s3://{bucket-name}
```

### Download & Install Artifacts on Test EC2 Instance

* **Note:** You may temporarily need to add AWS S3 IAM Permissions to the ECS Instance Role, do this using AWS IAM Console.
  * Run `aws sts get-caller-identity` on test EC2 Instance to get Instance Role Name, and add the policy `AmazonS3FullAccess` using the AWS IAM Console

```
 # On Test EC2 Instance
 # Stop running credentials-fetcher process
 sudo su
 systemctl stop credentials-fetcher
 
 # Remove existing binary and resources
 rm -rf /var/credentials-fetcher
 rm -f /usr/sbin/credentials-fetcher
 
 # Download new build artifacts
 aws s3 cp s3://{bucket-name}/credentials-fetcher /usr/sbin
 chmod +x /usr/sbin/credentials-fetcher
 aws s3 cp s3://{bucket-name}/credentials-fetcher.service /etc/systemd/system/
 aws s3 cp s3://{bucket-name}/credentials-fetcher.conf /etc/credentials-fetcher.conf
 
 # Startup New credentials-fetcher binary
systemctl daemon-reload
systemctl enable credentials-fetcher.service
systemctl start credentials-fetcher.service
systemctl status credentials-fetcher.service
systemctl restart ecs # only if testing with ECS 

# Optionally, tail logs
sudo journalctl -u credentials-fetcher.service -f
```

### Logs 

#### To tail the logs: 
```
sudo journalctl -u credentials-fetcher.service -f
```
#### To view logs from a timestamp:
```
journalctl --since "2025-01-08 21:00:00" | grep "credentials-fetcherd"
```

### ECS
1. To see credentials-fetcher in action in ECS, run `systemctl restart ecs`
2. Launch a new task from the AWS console
```bash
ECS > Credentials-fetcher-ecs-load-test > Tasks > Run new task
# Stop any currently running task
Task Definition Family : CredentialsFetcherADStackCredentialsFetcherTaskDefinitionTemplateXXXXXX-group-1
Compute Options: Launch Type
Launch Type: EC2
Networking VPC: Credentials-Fetcher-AD-Stack-vpc
Networking Security groups: Select all Security Groups
Hit Create
```
The task should successfully run and you should see the logs in the EC2 instance.

## 8. Runbook

### Setup Notes

* Replace all `{variable}` placeholders with your specific values
* Ensure proper AWS permissions for CDK deployment and Hydra execution
* Build packages in dependency order to avoid build failures
* When deploying to multiple regions, make sure to change the hardcoded region values in the `createDevEnvironment` function in `lib/app.ts`

### Common Issues

* Errors where SSM commands can't modify the AD, or you can’t Login to Windows Instance using Fleet Mgr
  * Domain Join Likely Failed, redeploy `InfraStack`
* SSM Commands failing to run
  * Instances may not have connected to SSM yet, this can take up to 10-15 mins after stack deployment
  * Windows Instance Domain Join may have failed,  redeploy `InfraStack`
* SSM `InvalidCommand` or `ParameterNotFound`
  * Double check that document/parmeter exists in AWS Console
  * Double check region is set correctly
* ECS Task Invocation fails with `Resource: MEMORY`
  * Test Cleanup Likely failed, goto ECS console and kill all running tasks.
* ECS Task Invocation fails with `ATTRIBUTE`
  * `credentials-fetcher` is not running or failed to install. Follow above installation steps to install manually
  * Check userData and journalctl logs in `var/log/cloud-init-output.log` and `journalctl -u credentials-fetcher` , respectively, to determine the Root cause
* Socket Issues
  * Likely Root Cause was `credentials-fetcher` was restarted after `ecs-agent` , instead of before. This will corrupt the `.sock` file
  * Run:

```
systemctl stop credentials-fetcher
rm -rf /var/credentials-fetcher
systemctl daemon-reload
systemctl start credentials-fetcher.service
systemctl restart ecs
```

* `credentials-fetcher` can’t login using `StandardUser01`
  * `StandardUser01` account was likely deleted, use the `CreateStandardUser` SSM Document to recreate it
* `sqlcmd` Authentication Failed
  * gMSA accounts were likely cleaned up, will need to spinup new SQL Server Instance by redeploying  `InfraStack`
  * `Create-ADGroup` SSM Document execution may have failed, therefore `StandardUser01` and/or Domain-Joined computer accounts may not be able to access gMSA accounts


## Related Packages

- [CredentialsFetcherV2Tests](https://code.amazon.com/packages/CredentialsFetcherV2Tests/trees/mainline#)
- [CredentialsFetcherV2CDK](https://code.amazon.com/packages/CredentialsFetcherV2CDK/trees/mainline)
- [CredentialsFetcherCanariesCDK](https://code.amazon.com/packages/CredentialsFetcherCanariesCDK/trees/mainline#)
