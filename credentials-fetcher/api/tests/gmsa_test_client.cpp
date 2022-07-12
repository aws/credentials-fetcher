#include <credentialsfetcher.grpc.pb.h>
#include <grpc++/grpc++.h>
#include <iostream>
#include <list>
#include <string>

#define unix_socket_address "unix:/usr/share/credentials-fetcher/socket/credentials_fetcher.sock"

/**
 * Testing client to validate grpc communication with server
 */
class CredentialsFetcherClient
{
  public:
    CredentialsFetcherClient( std::shared_ptr<grpc::Channel> channel )
        : _stub{ credentialsfetcher::CredentialsFetcherService::NewStub( channel ) }
    {
    }

    /**
     * Test method to create kerberos tickets
     * @param credspec_contents - information of service account
     * @return
     */

    std::string AddKerberosLeaseMethod( std::list<std::string> credspec_contents )
    {
        // Prepare request
        credentialsfetcher::CreateKerberosLeaseRequest request;
        for ( std::list<std::string>::const_iterator i = credspec_contents.begin();
              i != credspec_contents.end(); ++i )
        {
            request.add_credspec_contents( i->c_str() );
        }

        credentialsfetcher::CreateKerberosLeaseResponse response;
        grpc::ClientContext context;
        grpc::Status status;

        // Send request
        status = _stub->AddKerberosLease( &context, request, &response );

        // Handle response
        if ( status.ok() )
        {
            return response.lease_id();
        }
        else
        {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            return "RPC failed";
        }
    }

    /**
     * Test method to delete kerberos tickets
     * @param credspec_contents - lease_id corresponding to the tickets created
     * @return
     */
    std::string DeleteKerberosLeaseMethod( std::string lease_id )
    {
        // Prepare request
        credentialsfetcher::DeleteKerberosLeaseRequest request;
        request.set_lease_id( lease_id );

        credentialsfetcher::DeleteKerberosLeaseResponse response;
        grpc::ClientContext context;
        grpc::Status status;

        // Send request
        status = _stub->DeleteKerberosLease( &context, request, &response );

        // Handle response
        if ( status.ok() )
        {
            return response.lease_id();
        }
        else
        {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            return "RPC failed";
        }
    }

  private:
    std::unique_ptr<credentialsfetcher::CredentialsFetcherService::Stub> _stub;
};

int main( int argc, char** argv )
{
    std::string server_address{ unix_socket_address };
    CredentialsFetcherClient client{
        grpc::CreateChannel( server_address, grpc::InsecureChannelCredentials() ) };

    // create kerberos tickets
    std::list<std::string> credspec_contents = { "webapp01$@CONTOSO.COM", "webapp02$@CONTOSO.COM" };
    std::string add_response_field_lease_id = client.AddKerberosLeaseMethod( credspec_contents );
    std::cout << "Client received output for add kerberos lease: " << add_response_field_lease_id
              << std::endl;

    // delete kerberos tickets
    std::string lease_id = "lease_id";
    std::string delete_response_field_lease_id = client.DeleteKerberosLeaseMethod( lease_id );
    std::cout << "Client received output for delete kerberos lease: "
              << delete_response_field_lease_id << std::endl;

    return 0;
}