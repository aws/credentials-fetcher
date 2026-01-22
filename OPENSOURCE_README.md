# Credentials Fetcher

credentials-fetcher is a Linux daemon that retrieves gMSA credentials from Active Directory over LDAP. It creates and refreshes kerberos tickets from gMSA credentials. Kerberos tickets can be used by containers to run apps/services that authenticate using Active Directory.

This daemon works in a similar way as ccg.exe and the gMSA plugin in Windows as described in - https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts#gmsa-architecture-and-improvements

## Table of Contents
- [Prerequisites](#prerequisites)
- [Building from Source](#building-from-source)
- [Installation](#installation)
- [Configuration](#configuration)
- [Setting up Testing Environment](#setting-up-testing-environment)
- [Testing](#testing)
- [Service Management](#service-management)
- [Troubleshooting](#troubleshooting)

## Prerequisites

**Supported Platforms:** Amazon Linux 2023 (recommended), Fedora 41+

**Required Dependencies:**
```bash
dnf install openldap-clients krb5-workstation sssd 
```

**For Domain-Joined Mode (additional):**
```bash
dnf install realmd oddjob oddjob-mkhomedir adcli
```

**For Testing:**
```bash
pip install grpcio grpcio-tools
```

**Build Dependencies (AL2023):**
```bash
# Install Go
sudo dnf install -y golang

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Add to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

## Building from Source

### Quick Build
```bash
make build
```

The binary will be created at `bin/credentials-fetcherd`.

### Build Options

| Command | Description |
|---------|-------------|
| `make build` | Build the binary |
| `make lint-check` | Run golangci-lint |
| `make security-check` | Run gosec security scanner |
| `make release-strict` | Full build with security checks, linting, and race detection |
| `make cf-install` | Build and install to system (requires sudo) |
| `make cf-create-service` | Generate systemd service file |

### Build Flags

Enable debugging symbols:
```bash
ENABLE_DEBUGGING=1 make build
```

Enable code coverage:
```bash
CODE_COVERAGE=1 make build
```

### Manual Installation

After building:
```bash
sudo make cf-install
```

This installs:
- Binary to `/usr/sbin/credentials-fetcherd`
- Service file to `/usr/lib/systemd/system/credentials-fetcher.service`
- Config to `/etc/credentials-fetcher.conf`

## Installation

### Installing the latest version of credentials-fetcher

```bash
dnf install credentials-fetcher
```

### Verify Installation
```bash
systemctl status credentials-fetcher
credentials-fetcher --version
```

## Configuration

The daemon is configured via `/etc/credentials-fetcher.conf`.

**For ECS/Fargate (managed modes):** No configuration needed. Default settings work out of the box.

**For standalone mode:** All options remain optional for basic lease operations. Configuration is only needed if you require automatic credential renewal in non-domain joined standalone deployments.

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `RunRenewalNonDomainJoined` | bool | false | Enable automatic credential renewal for non-domain joined standalone mode |
| `CFGmsaSecretName` | string | "" | AWS Secrets Manager secret name containing AD credentials |
| `LDAPSearchTimeout` | int | 5 | LDAP search timeout in seconds |

### Default Configuration (ECS/Fargate/Standalone)

Works for all deployment modes without modification:

```ini
# /etc/credentials-fetcher.conf
RunRenewalNonDomainJoined =
CFGmsaSecretName = ""
LDAPSearchTimeout = 5
```

### Standalone Non-Domain-Joined with Auto-Renewal

Only needed for standalone deployments requiring automatic credential renewal:

```ini
# /etc/credentials-fetcher.conf
RunRenewalNonDomainJoined = true
CFGmsaSecretName = "prod/ad-credentials"
LDAPSearchTimeout = 10
```

AWS Secrets Manager secret format:
```json
{"username": "StandardUser01", "password": "p@ssw0rd", "domainName": "contoso.com"}
```

## Setting up testing environment

### Setting up gMSA accounts
Setup gMSA accounts using instructions [here](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts#one-time-preparation-of-active-directory). Both domain-joined and non-domain joined use cases are supported. In Fargate, only non-domain joined is supported.

### Setting up domain credentials to retrieve gMSA password

In non domain joined modes, the AD User credentials need to be stored in a secret store that will be retrieved by the daemon. We use AWS Secret Manager for this. 

Save the AD User credentials to AWS secrets manager

```json
{
    "username":"StandardUser01",
    "password":"p@ssw0rd",
    "domainName":"contoso.com"
}
```

Next, on the EC2 instance where credentials-fetcher is installed, navigate to /etc/credentials-fetcher.conf and provide the secrets manager name

For domain joined modes, the host principle needs to be part of the group that is allowed to retrieve the managed password in AD setup.

## Testing

Once gMSA accounts are created, use the test scripts in `tests/test_scripts/` to validate kerberos ticket functionality.

### Quick Test Setup

1. **Install Python dependencies:**
   ```bash
   pip install grpcio grpcio-tools
   ```

2. **Generate gRPC Python files:**
   ```bash
   cd tests/test_scripts
   python -m grpc_tools.protoc --proto_path=../../internal/grpc --python_out=. --grpc_python_out=. credentialsfetcher.proto
   ```

3. **Start credentials-fetcher daemon:**
   ```bash
   sudo systemctl start credentials-fetcher
   ```

### Running Tests

**Domain-joined mode:**
```bash
# Replace {CREDSPEC_PLACEHOLDER} with your credspec JSON
python add_kerberos_lease_test.py

# Delete lease (replace {LEASE_ID_PLACEHOLDER} with returned lease_id)
python delete_kerberos_lease_test.py
```

**Non-domain-joined mode:**
```bash
# Replace {CREDSPEC_PLACEHOLDER} and {PASSWORD_PLACEHOLDER} with actual values
python add_non_domain_joined_kerberos_lease_test.py

# Test renewal
python renew_non_domain_joined_kerberos_lease.py
```

**Expected output:** Scripts print `GRPC_TEST_RESULT:` followed by JSON with success status and lease details.

### Sample Credspec

**Domain-Joined Mode:**
```json
{
    "CmsPlugins": ["ActiveDirectory"],
    "DomainJoinConfig": {
        "Sid": "S-1-5-21-123456789-123456789-123456789",
        "MachineAccountName": "WebApp01",
        "Guid": "af602f85-d754-4eea-9fa8-fd76810485f1",
        "DnsTreeName": "contoso.com",
        "DnsName": "contoso.com",
        "NetBiosName": "CONTOSO"
    },
    "ActiveDirectoryConfig": {
        "GroupManagedServiceAccounts": [
            {
                "Name": "WebApp01",
                "Scope": "contoso.com"
            }
        ]
    }
}
```

**Non-Domain-Joined Mode:**
```json
{
    "CmsPlugins": ["ActiveDirectory"],
    "DomainJoinConfig": {
        "Sid": "S-1-5-21-987654321-987654321-987654321",
        "MachineAccountName": "WebApp02",
        "Guid": "bf702f85-e864-5ffa-8gb9-ge87920596g2",
        "DnsTreeName": "contoso.com",
        "DnsName": "contoso.com",
        "NetBiosName": "CONTOSO"
    },
    "ActiveDirectoryConfig": {
        "GroupManagedServiceAccounts": [
            {
                "Name": "WebApp02",
                "Scope": "contoso.com"
            }
        ],
        "HostAccountConfig": {
            "PortableCcgVersion": "1",
            "PluginGUID": "{859E1386-BDB4-49E8-85C7-3070B13920E1}",
            "PluginInput": "prod/ad-credentials"  // AWS Secrets Manager secret name
        }
    }
}
```

## Service Management

```bash
# Start the service
sudo systemctl start credentials-fetcher

# Stop the service
sudo systemctl stop credentials-fetcher

# Check status
sudo systemctl status credentials-fetcher

# Enable auto-start
sudo systemctl enable credentials-fetcher

# View logs
sudo journalctl -u credentials-fetcher -f
```

## Troubleshooting

### Common Issues

**Service won't start:**
- Check logs: `sudo journalctl -u credentials-fetcher`
- Verify config file: `/etc/credentials-fetcher.conf`
- Ensure socket directory exists: `/var/credentials-fetcher/socket`

**LDAP connection failures:**
- Verify AD connectivity: `ldapsearch -H ldap://your-dc.contoso.com`
- Check DNS resolution: `nslookup your-dc.contoso.com`
- Validate credentials in AWS Secrets Manager

**Kerberos ticket issues:**
- Check ticket cache: `klist -c /var/credentials-fetcher/krbdir/*/krb5cc_*`
- Verify time sync: `timedatectl status`
- Test kinit manually: `kinit username@DOMAIN.COM`

**Test script failures:**
- Ensure daemon is running: `systemctl status credentials-fetcher`
- Check socket permissions: `ls -la /var/credentials-fetcher/socket/`
- Verify gRPC files generated: `ls -la tests/test_scripts/*_pb2.py`

### Log Locations
- Service logs: `journalctl -u credentials-fetcher`
- Application logs: `/var/log/credentials-fetcher/` (if configured)
- Kerberos cache: `/var/credentials-fetcher/krbdir/`



