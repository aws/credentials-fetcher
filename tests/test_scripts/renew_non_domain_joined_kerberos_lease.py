import grpc
import credentialsfetcher_pb2
import credentialsfetcher_pb2_grpc
import json

def run():
    try:
        with grpc.insecure_channel('unix:///var/credentials-fetcher/socket/credentials_fetcher.sock') as channel:
            stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
            response = stub.RenewNonDomainJoinedKerberosLease(
                credentialsfetcher_pb2.RenewNonDomainJoinedKerberosLeaseRequest(
                    username="StandardUser01",
                    password="{PASSWORD_PLACEHOLDER}",
                    domain="contoso.com"
                )
            )

            # Print result in expected format
            result = {
                'success': True,
                'renewed_kerberos_file_paths': list(response.renewed_kerberos_file_paths)
            }
            print(f"GRPC_TEST_RESULT:{json.dumps(result)}")

    except Exception as e:
        result = {
            'success': False,
            'error': str(e)
        }
        print(f"GRPC_TEST_RESULT:{json.dumps(result)}")

if __name__ == '__main__':
    run()
