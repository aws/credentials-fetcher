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
brazil-recursive-cmd --allPackages brazil-build release
```

### Run Tests

```bash
# Navigate to the test directory
cd src/CredentialsFetcherV2Tests

# Run tests
brazil-build test
```

## Related Packages

- [CredentialsFetcherV2Tests](https://code.amazon.com/packages/CredentialsFetcherV2Tests/trees/mainline#)
- [CredentialsFetcherV2CDK](https://code.amazon.com/packages/CredentialsFetcherV2CDK/trees/mainline)
- [CredentialsFetcherCanariesCDK](https://code.amazon.com/packages/CredentialsFetcherCanariesCDK/trees/mainline#)
