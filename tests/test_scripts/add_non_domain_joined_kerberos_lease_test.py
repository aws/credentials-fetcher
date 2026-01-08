import grpc
import credentialsfetcher_pb2
import credentialsfetcher_pb2_grpc
import json

def run():
    try:
        with grpc.insecure_channel('unix:///var/credentials-fetcher/socket/credentials_fetcher.sock') as channel:
            stub = credentialsfetcher_pb2_grpc.CredentialsFetcherServiceStub(channel)
            credspec_contents = '''{CREDSPEC_PLACEHOLDER}'''
            contents = []
            contents += [credspec_contents]
            response = stub.AddNonDomainJoinedKerberosLease(
                credentialsfetcher_pb2.CreateNonDomainJoinedKerberosLeaseRequest(
                    credspec_contents=contents,
                    username="StandardUser01",
                    password="{PASSWORD_PLACEHOLDER}",
                    domain="contoso.com"
                )
            )

            # Extract lease_id from response
            lease_id = response.lease_id

            # Print result in expected format
            result = {
                'success': True,
                'lease_id': lease_id,
                'created_kerberos_file_paths': list(response.created_kerberos_file_paths)
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