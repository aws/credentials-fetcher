# CredentialsFetcherV2

## Overview

This package is the Golang refactor of [credentials-fetcher](https://github.com/aws/credentials-fetcher).

## Getting Started

### Setup Brazil Workspace

```bash
# Create the workspace
brazil ws create --root CredentialsFetcherV2 --vs CredentialsFetcherV2/development

# Change to workspace directory and use required packages
cd CredentialsFetcherV2 && brazil ws use --p CredentialsFetcherV2 --p CredentialsFetcherV2Tests --p CredentialsFetcherV2CDK
```

## Build and Test

### Build Packages

```bash
# Navigate to CDK directory
cd src/CredentialsFetcherV2

# Build all packages
brazil-build
```

### Prerequisites

The following dependencies are needed on the instance

```
dnf install openldap-clients krb5-workstation sssd 
```

For domain joined mode, the following additional dependencies are needed to domain join the instance to the realm
```
dnf install realmd oddjob oddjob-mkhomedir adcli
```

### Development and Testing

It is recommended to develop on AL (ex: cloud desktop). To test any changes, an EC2 instance with Active Directory setup is a requirement.
1. Setup the cdk stack according to the instructions [here](https://github.com/aws/credentials-fetcher/blob/dc5c2caec5e78052327b39cf2528eea7b2f45c91/cdk/cdk-domainless-mode/README.md).
2. Create a binary with the latest changes using `brazil-build`.
3. The binary is created at `bin/credentials-fetcherd`
3. `scp` this binary to the EC2 instance setup above, along with the `service/credentials-fetcher.service` file
4. SSH into the EC2 instance and run the following
```
sudo cp credentials-fetcherd /usr/local/bin
sudo chmod +x /usr/local/bin/credentials-fetcher
sudo cp credentials-fetcher.service /etc/systemd/system/
```
5. Start the service
```
sudo systemctl daemon-reload
sudo systemctl enable credentials-fetcher.service
sudo systemctl start credentials-fetcher.service
sudo systemctl status credentials-fetcher.service
```
6. To tail the logs
```
sudo journalctl -u credentials-fetcher.service -f
```


### Building RPM Packages

The service stack includes infrastructure for building RPM packages. The spec file supports dynamic versioning for CI/CD integration.

#### RPM Versioning Strategy

- Production releases follow semantic versioning: `2.0.0`, `2.0.1`, etc.
- CI builds can use build numbers or timestamps for continuous integration

#### Building RPM Locally

1. Install required dependencies:
   ```bash
   sudo yum install -y golang systemd-devel rpm-build rpmdevtools
   ```

2. Prepare the source tarball (replace VERSION with desired version):
   ```bash
   export VERSION=2.0.0
   mkdir -p /tmp/credentials-fetcher-$VERSION
   cp -r ~/workplace/CredentialsFetcherV2/src/CredentialsFetcherV2/* /tmp/credentials-fetcher-$VERSION/
   ```

3. Build the RPM with default version (2.0.0):
   ```bash
   mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
   cp /tmp/credentials-fetcher-$VERSION/configuration/SPECS/credentials-fetcher.spec ~/rpmbuild/SPECS/
   tar -czf ~/rpmbuild/SOURCES/credentials-fetcher-$VERSION.tar.gz -C /tmp credentials-fetcher-$VERSION
   rpmbuild -ba ~/rpmbuild/SPECS/credentials-fetcher.spec
   ```

4. Build with custom version and release number:
   ```bash
   # For production releases (e.g., 2.0.1)
   rpmbuild -ba ~/rpmbuild/SPECS/credentials-fetcher.spec --define "version 2.0.1" --define "release 1"
   
   # For CI builds (using timestamp or build number)
   rpmbuild -ba ~/rpmbuild/SPECS/credentials-fetcher.spec --define "version 2.0.0" --define "release 0.$(date +%Y%m%d%H%M)"
   ```

5. The built RPM will be available at:
   ```
   ~/rpmbuild/RPMS/x86_64/credentials-fetcher-<version>-<release>.<arch>.rpm
   ```

#### CI/CD Integration

For CI/CD pipelines, you can automatically generate version numbers:

- Production releases: Increment the last number (2.0.0 → 2.0.1 → 2.0.2)
- Development builds: Use timestamp or CI build number as release (2.0.0-0.20250605.1)


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

### Standalone
1. Run the python script [here](https://github.com/aws/credentials-fetcher/blob/mainline/cdk/cdk-domainless-mode/test-scripts/add_delete_kerberos_leases.py).
2. See the Kerberos leases being added and delete in the jounrnalctl logs.

## Related Packages

- [CredentialsFetcherV2Tests](https://code.amazon.com/packages/CredentialsFetcherV2Tests/trees/mainline#)
- [CredentialsFetcherV2CDK](https://code.amazon.com/packages/CredentialsFetcherV2CDK/trees/mainline)
- [CredentialsFetcherCanariesCDK](https://code.amazon.com/packages/CredentialsFetcherCanariesCDK/trees/mainline#)

