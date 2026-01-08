import grpc
import credentialsfetcher_pb2
import credentialsfetcher_pb2_grpc
import json

def run():
    try:
        with grpc.insecure_channel('unix:///var/credentials-fetcher/socket/credentials_fetcher.sock') as channel:
            stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
            credspec_contents = '''{CREDSPEC_PLACEHOLDER}'''
            contents = [credspec_contents]
            response = stub.AddKerberosLease(credentialsfetcher_pb2.CreateKerberosLeaseRequest(credspec_contents=contents))
            
            # Output response in JSON format for easier parsing
            result = {
                "success": True,
                "lease_id": response.lease_id,
                "created_kerberos_file_paths": list(response.created_kerberos_file_paths)
            }
            print("GRPC_TEST_RESULT:" + json.dumps(result))
            return response.lease_id
    except Exception as e:
        result = {
            "success": False,
            "error": str(e)
        }
        print("GRPC_TEST_RESULT:" + json.dumps(result))
        raise

if __name__ == '__main__':
    run()
