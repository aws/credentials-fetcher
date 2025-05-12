#!/bin/bash

# Create coverage output directory if it doesn't exist
mkdir -p coverage

# Run tests with coverage
go test ./... -coverprofile=coverage/coverage.out -coverpkg=$(go list ./... | grep -v -E "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto|golang.a2z.com/CredentialsFetcherV2/tests/test_client|golang.a2z.com/CredentialsFetcherV2/cmd/credentials-fetcher" | tr '\n' ',')

# Generate HTML coverage report
go tool cover -html=coverage/coverage.out -o coverage/coverage.html

# Display coverage statistics
go tool cover -func=coverage/coverage.out
