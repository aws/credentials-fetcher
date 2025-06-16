#!/usr/bin/env python3

import grpc
import os
import sys
import json
from pathlib import Path

# This script tests only the AddKerberosArnLease API with hardcoded values
# but takes AWS credentials from environment variables

try:
    import credentialsfetcher_pb2
    import credentialsfetcher_pb2_grpc
except ImportError:
    print("Error: credentialsfetcher_pb2 and credentialsfetcher_pb2_grpc modules not found.")
    print("Please generate them using: python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. credentialsfetcher.proto")
    sys.exit(1)

# Unix socket path for the credentials-fetcher daemon
UNIX_SOCKET_PATH = 'unix:///var/credentials-fetcher/socket/credentials_fetcher.sock'

# Get AWS credentials from environment variables
def get_env_var(var_name):
    value = os.environ.get(var_name)
    if not value:
        print(f"Error: Environment variable {var_name} is not set")
        sys.exit(1)
    return value

# Hardcoded test value
TEST_CREDSPEC_ARN = "arn:aws:s3:::muskanl-credentials-fetcher-pre-created-bucket/WebApp01_credspec.json"
TEST_REGION = "us-west-2"

# AWS credentials from environment variables
TEST_ACCESS_KEY_ID = get_env_var("AWS_ACCESS_KEY_ID")
TEST_SECRET_ACCESS_KEY = get_env_var("AWS_SECRET_ACCESS_KEY")
TEST_SESSION_TOKEN = get_env_var("AWS_SESSION_TOKEN")

def add_kerberos_arn_lease():
    """Test the AddKerberosArnLease API"""
    print("Testing AddKerberosArnLease API...")
    
    try:
        # Create a gRPC channel to the Unix domain socket
        channel = grpc.insecure_channel(UNIX_SOCKET_PATH)
        stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
        
        # Create the ARN with a fragment identifier
        arn_with_fragment = f"{TEST_CREDSPEC_ARN}#123/WebApp01"
        
        # Create the request
        request = credentialsfetcher_pb2.KerberosArnLeaseRequest(
            credspec_arns=[arn_with_fragment],
            access_key_id=TEST_ACCESS_KEY_ID,
            secret_access_key=TEST_SECRET_ACCESS_KEY,
            session_token=TEST_SESSION_TOKEN,
            region=TEST_REGION
        )
        
        # Call the API
        response = stub.AddKerberosArnLease(request)
        
        # Print the response
        print(f"Lease ID: {response.lease_id}")
        print("Kerberos ticket responses:")
        for ticket in response.krb_ticket_response_map:
            print(f"  - ARN: {ticket.credspec_arns}")
            print(f"    Path: {ticket.created_kerberos_file_paths}")
            
            # Verify the file exists
            krb5cc_path = f"{ticket.created_kerberos_file_paths}/krb5cc"
            if os.path.exists(krb5cc_path):
                print(f"    ✓ Verified file exists: {krb5cc_path}")
            else:
                print(f"    ✗ File does not exist: {krb5cc_path}")
        
        return response.lease_id
    except grpc.RpcError as e:
        print(f"API call failed: {e.code()}: {e.details()}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    print("Starting AddKerberosArnLease API test...")
    lease_id = add_kerberos_arn_lease()
    
    if lease_id:
        print(f"\nTest completed successfully. Lease ID: {lease_id}")
    else:
        print("\nTest failed.")
        sys.exit(1)
