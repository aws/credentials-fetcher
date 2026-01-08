import grpc
import credentialsfetcher_pb2
import credentialsfetcher_pb2_grpc
import os

def delete_lease():
    try:
        with grpc.insecure_channel('unix:///var/credentials-fetcher/socket/credentials_fetcher.sock') as channel:
            stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
            delete_response = stub.DeleteKerberosLease(
                credentialsfetcher_pb2.DeleteKerberosLeaseRequest(
                    lease_id="{LEASE_ID_PLACEHOLDER}"
                )
            )
            print(f"Deleted lease: {delete_response.lease_id}")
            lease_path = f"/var/credentials-fetcher/krbdir/{LEASE_ID_PLACEHOLDER}"
            print(f"Checking lease path: {lease_path}")
            if not os.path.exists(lease_path):
                print("LEASE_DELETE_SUCCESS: Lease directory removed")
            else:
                print("LEASE_DELETE_FAILED: Lease directory still exists")
    except Exception as e:
        print(f"LEASE_DELETE_ERROR: {str(e)}")

if __name__ == '__main__':
    delete_lease()
