# gRPC Server for Credentials Fetcher V2

This directory contains the gRPC server implementation for the Credentials Fetcher V2 service. The server handles credential requests and provides authentication services through a well-defined gRPC API.

## Directory Structure

- `credentialsfetcher.proto`: Protocol Buffer definition file that defines the service interface
- `credentialsfetcher.pb.go`: Auto-generated Go code from the proto file
- `credentialsfetcher_grpc.pb.go`: Auto-generated gRPC service code
- `server.go`: Main server implementation


## Adding a New API

When you need to add a new API endpoint to the gRPC service, follow these steps:

1. **Update the Proto File**:
   - Edit `credentialsfetcher.proto` to add your new service method
   - Define request and response message types for your new API

2. **Generate Updated Go Code**:
   ```bash
   # Navigate to the project root
   cd /CredentialsFetcherV2
   
   # Install protoc compiler if not already installed
   # This step may vary depending on your environment
   
   # Generate Go code from the updated proto file
   protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       internal/grpc/credentialsfetcher.proto
   ```

3. **Implement the Service Method**:
   - Add the implementation of your new service method in `server.go` or create a new file if needed
   - Make sure your implementation satisfies the interface defined in the generated code

4. **Write Tests**:
   - Create unit tests for your new API endpoint
   - Ensure proper error handling and edge cases are covered

5. **Update Documentation**:
   - Document your new API in relevant documentation files
   - Include examples of how to use the new API


## Best Practices

- Keep the proto definitions clean and well-documented
- Follow gRPC naming conventions
- Use appropriate error codes and error messages
- Consider backward compatibility when updating existing APIs
- Add proper validation for all input parameters
