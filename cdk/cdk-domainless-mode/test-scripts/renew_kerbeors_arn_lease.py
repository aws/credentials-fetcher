#!/usr/bin/env python3

import grpc
import os
import sys
import json
from pathlib import Path

# This script tests the RenewKerberosArnLease API with AWS credentials from environment variables
# It should be run after test_add_kerberos_arn_lease.py has been executed successfully

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

with open('../data.json', 'r') as file:
    # Load the JSON data
    data = json.load(file)
    
TEST_REGION = data["aws_region"]


# AWS credentials from environment variables
TEST_ACCESS_KEY_ID = get_env_var("AWS_ACCESS_KEY_ID")
TEST_SECRET_ACCESS_KEY = get_env_var("AWS_SECRET_ACCESS_KEY")
TEST_SESSION_TOKEN = get_env_var("AWS_SESSION_TOKEN")

def renew_kerberos_arn_lease():
    """Test the RenewKerberosArnLease API"""
    print("Testing RenewKerberosArnLease API...")
    
    try:
        # Create a gRPC channel to the Unix domain socket
        channel = grpc.insecure_channel(UNIX_SOCKET_PATH)
        stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
        
        # Create the request
        request = credentialsfetcher_pb2.RenewKerberosArnLeaseRequest(
            access_key_id=TEST_ACCESS_KEY_ID,
            secret_access_key=TEST_SECRET_ACCESS_KEY,
            session_token=TEST_SESSION_TOKEN,
            region=TEST_REGION
        )
        
        # Call the API
        response = stub.RenewKerberosArnLease(request)
        
        # Print the response
        print(f"Status: {response.status}")
        
        # Since the response doesn't include file paths, we need to check the kerberos directory
        # to verify the tickets were renewed
        krb_dir = "/var/credentials-fetcher/krbdir"
        if os.path.exists(krb_dir):
            print("\nChecking for renewed Kerberos tickets in directory:")
            import time
            current_time = time.time()
            
            # List all lease directories
            lease_dirs = [d for d in os.listdir(krb_dir) if os.path.isdir(os.path.join(krb_dir, d))]
            if lease_dirs:
                for lease_dir in lease_dirs:
                    lease_path = os.path.join(krb_dir, lease_dir)
                    print(f"\nLease directory: {lease_path}")
                    
                    # List all account directories within this lease
                    account_dirs = [d for d in os.listdir(lease_path) if os.path.isdir(os.path.join(lease_path, d))]
                    for account_dir in account_dirs:
                        account_path = os.path.join(lease_path, account_dir)
                        krb5cc_path = os.path.join(account_path, "krb5cc")
                        
                        if os.path.exists(krb5cc_path):
                            mtime = os.path.getmtime(krb5cc_path)
                            time_diff = current_time - mtime
                            
                            print(f"  Account: {account_dir}")
                            print(f"    Path: {krb5cc_path}")
                            print(f"    ✓ Ticket file exists")
                            
                            if time_diff < 60:  # If file was modified in the last minute
                                print(f"    ✓ Ticket was recently renewed ({time_diff:.2f} seconds ago)")
                            else:
                                print(f"    ⚠ Ticket may not have been renewed (last modified {time_diff:.2f} seconds ago)")
                        else:
                            print(f"  Account: {account_dir}")
                            print(f"    ✗ Ticket file does not exist: {krb5cc_path}")
            else:
                print("  No lease directories found")
        else:
            print(f"  ✗ Kerberos directory not found: {krb_dir}")
        
        return response.status
    except grpc.RpcError as e:
        print(f"API call failed: {e.code()}: {e.details()}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    print("Starting RenewKerberosArnLease API test...")
    status = renew_kerberos_arn_lease()
    
    if status:
        print(f"\nTest completed successfully. Status: {status}")
    else:
        print("\nTest failed.")
        sys.exit(1)
