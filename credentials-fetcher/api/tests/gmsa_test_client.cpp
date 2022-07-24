#include <credentialsfetcher.grpc.pb.h>
#include <grpc++/grpc++.h>
#include <iostream>
#include <list>
#include <string>

#define unix_socket_address "unix:/usr/share/credentials-fetcher/socket/credentials_fetcher.sock"

/**
 * Testing client to validate grpc communication with server
 * Testing client to validate grpc communication with server, we need the client to mimic client
 * server communication behaviour
 * Invocation of the server can either be done from client or using grpc_cli
 *
 * Example cli invocations:
 * -------------------------
 * AddKerberoslease : grpc_cli {path_of_domain_sock}/credentials_fetcher.sock AddKerberoslease
 * "'cred_contents = {"webapp01$@CONTOSO.COM", "webapp02$@CONTOSO.COM"}'"
 * DeleteKerberoslease : grpc_cli {path_of_domain_sock}/credentials_fetcher.sock
 * "'DeleteKerberoslease "'lease_id = lease_id'"
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
            for ( int i = 0; i < response.created_kerberos_file_paths_size(); i++ )
            {
                std::cout << "created ticket file " + response.created_kerberos_file_paths( i )
                          << std::endl;
            }
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
            for ( int i = 0; i < response.deleted_kerberos_file_paths_size(); i++ )
            {
                std::cout << "deleted ticket file " + response.deleted_kerberos_file_paths( i )
                          << std::endl;
            }
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

static void show_usage( std::string name )
{
    std::cout
        << "Usage: " << name << " <option(s)> SOURCES"
        << "Options:\n"
        << "\t-h,--help\t\tShow this help message\n"
        << "\t-no option\t\tcreate & delete kerberos tickets\n"
        << "\t -create \t\tcreate krb tickets for service account\n"
        << "\t -delete \t\tdelete krb tickets for a given lease_id\tprovide lease_id to be "
           "deleted\n"
        << "\t -invalidargs \t\ttest with invalid args, failure scenario\n"
        << std::endl;
}

// create kerberos tickets
std::string create_krb_ticket( CredentialsFetcherClient &client, std::list<std::string>
    credspec_contents )
{
    std::string add_response_field_lease_id = client.AddKerberosLeaseMethod( credspec_contents );
    std::cout << "Client received output for add kerberos lease: " << add_response_field_lease_id
              << std::endl;
    return add_response_field_lease_id;
}

// delete kerberos tickets
std::string delete_krb_ticket( CredentialsFetcherClient &client, std::string lease_id )
{
    std::string delete_response_field_lease_id = client.DeleteKerberosLeaseMethod( lease_id );
    std::cout << "Client received output for delete kerberos lease: "
              << delete_response_field_lease_id << std::endl;
    return delete_response_field_lease_id;
}

int main( int argc, char** argv )
{
    std::string lease_id;
    std::string server_address{ unix_socket_address };
    CredentialsFetcherClient client{
        grpc::CreateChannel( server_address, grpc::InsecureChannelCredentials() ) };

    std::list<std::string> credspec_contents = {
        "{\"CmsPlugins\":[\"ActiveDirectory\"],"
        "\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\","
        "\"MachineAccountName\":\"WebApp01\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\","
        "\"DnsTreeName\":\"contoso.com\",\"DnsName\":\"contoso.com\",\"NetBiosName\":\"contoso\"},"
        "\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"WebApp01\","
        "\"Scope\":\"contoso.com\"},{\"Name\":\"WebApp01\",\"Scope\":\"contoso\"}]}}",
        "{\"CmsPlugins\":[\"ActiveDirectory\"],"
        "\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\","
        "\"MachineAccountName\":\"WebApp03\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\","
        "\"DnsTreeName\":\"contoso.com\",\"DnsName\":\"contoso.com\",\"NetBiosName\":\"contoso\"},"
        "\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"WebApp03\","
        "\"Scope\":\"contoso.com\"},{\"Name\":\"WebApp03\",\"Scope\":\"contoso\"}]}}" };

    std::list<std::string> invalid_credspec_contents = {
        "{\"CmsPlugins\":[\"ActiveDirectory\"],"
        "\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\","
        "\"MachineAccountName\":\"WebApp01\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\","
        "\"DnsTreeName\":\"contoso.com\",\"NetBiosName\":\"contoso\"}," };

    // create and delete krb tickets
    if ( argc == 1 )
    {
        lease_id = create_krb_ticket( client, credspec_contents );
        delete_krb_ticket( client, lease_id );
    }

    for ( int i = 1; i < argc; ++i )
    {
        std::string arg = argv[i];
        if ( ( arg == "-h" ) || ( arg == "--help" ) )
        {
            show_usage( argv[0] );
            return 0;
        }
        else if ( arg == "-delete" )
        {
            if ( i + 1 < argc )
            {
                lease_id = argv[i + 1];
            }
            else
            {
                std::cout << "--delete option requires lease_id argument." << std::endl;
                return 0;
            }
            std::cout << "krb tickets will get deleted for a given lease_id" << std::endl;
            delete_krb_ticket( client, lease_id );
            i++;
        }
        else if ( arg == "-create" )
        {
            std::cout << "krb tickets will get created" << std::endl;
            create_krb_ticket( client, credspec_contents );
        }
        else if ( arg == "-invalidargs" )
        {
            std::cout << "test for invalid args" << std::endl;
            create_krb_ticket( client, invalid_credspec_contents );
        }
        else
        {
            std::cout << "provide a valid arg, for help use -h or --help" << std::endl;
            return 0;
        }
    }
    return 0;
}

