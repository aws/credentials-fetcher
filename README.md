## Overview

This package is an example Go Lambda package for using with CDK Pipeline. It
doesn't have an API Gateway definition associated with it. It's most useful when
you just want to deploy a lambda function, perhaps for use as a stream consumer,
or invoked by SQS, SNS, or CloudWatch.

This package does not contain any deployment logic, that is defined in the
CredentialsFetcherV2CDK package.

## Development

For development with this package here's our current recommendation:

1. Binaries go in the `cmd` directory; ones prefixed with `lambda` will be
   automatically placed in a zip of the same name.
2. Internal logic goes in the `internal` directory; this prevents consumers of
   this package from taking a dependency on any exported functions or types.
   Unless you are writing a library you likely want all logic to be "internal".

## Debugging

By default, debugging information is stripped out of binaries built using
`brazil-build`. To disable this comment out the `GO_INSTALL_FLAGS` line in the
`Makefile`.

## Testing

For testing with this package here's our current recommendation:

1. Unit tests. Run good old-fashioned unit tests against your code with
   `brazil-build test`.
2. Lint check. Run the linter against your code with `brazil-build lint-check`.
3. Security check. Run a security check against your code with
   `brazil-build security-check`.
4. Deploy to your personal stack and validate the functionalities there. This
   needs to be done in two steps:
   1. Run `brazil-build` in this package.
   2. `brazil-build cdk deploy --hotswap CredentialsFetcherV2-Service-Personal` in
      the CredentialsFetcherV2CDK package.
5. Send out a CR, get approval, and push (or merge from CRUX).
6. Run integration tests in your pipeline for your function.
