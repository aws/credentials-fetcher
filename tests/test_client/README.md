# Health Check Client

This is a standalone client for testing the health check functionality of the Credentials Fetcher service. It's based on the same client implementation used by the Amazon ECS Agent.

## Overview

The health check client connects to the Credentials Fetcher service via a Unix socket and makes a health check request. This is useful for:

1. Verifying that the service is running and responding to requests
2. Testing the health check functionality in isolation
3. Monitoring the service health in production environments

## Usage

```bash
./health_check_client [options]
```

### Options

- `-socket`: Path to the Unix socket (default: "/var/credentials-fetcher/socket/credentials_fetcher.sock")
- `-service`: Service name to include in the health check request (default: "health-check-client")
- `-timeout`: Timeout for the health check request (default: 5s)

### Example

```bash
./health_check_client -socket=/var/credentials-fetcher/socket/credentials_fetcher.sock
```

## Building

```bash
cd /CredentialsFetcherV2/tests/test_client
bb go build -o health_check_client health_check_client.go
```

## Integration with ECS Agent

This client implements the same health check functionality as the Amazon ECS Agent's gMSA credentials client. It can be used to verify that the Credentials Fetcher service is running correctly and that the health check RPC is functioning as expected.
