#include <chrono>
#include <credentialsfetcher.grpc.pb.h>
#include <ctime>
#include <errno.h>
#include <exception>
#include <fstream>
#include <grpc++/grpc++.h>
#include <iostream>
#include <list>
#include <random>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>

#define unix_socket_address "unix:/var/credentials-fetcher/socket/credentials_fetcher.sock"

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

    std::pair<std::string, std::list<std::string>> AddKerberosLeaseMethod(
        std::list<std::string> credspec_contents )
    {
        // Prepare request
        std::list<std::string> krb_ticket_paths;
        credentialsfetcher::CreateKerberosLeaseRequest request;
        std::pair<std::string, std::list<std::string>> result;
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
                std::string msg =
                    "created ticket file " + response.created_kerberos_file_paths( i );
                krb_ticket_paths.push_back( msg );
                std::cout << msg << std::endl;
            }
            result = std::pair<std::string, std::list<std::string>>( response.lease_id(),
                                                                     krb_ticket_paths );
            return result;
        }
        else
        {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            result =
                std::pair<std::string, std::list<std::string>>( "RPC failed", krb_ticket_paths );
            return result;
        }
    }

    /**
     * Test method to create kerberos tickets in non domain joined mode
     * @param credspec_contents - information of service account
     * @param username - username for the AD user
     * @param password - password for the AD user
     * @param domain - domain associated to gMSA account
     * @return
     */

    std::pair<std::string, std::list<std::string>> AddNonDomainJoinedKerberosLeaseMethod(
        std::list<std::string> credspec_contents, std::string username, std::string password, std::string domain )
    {
        // Prepare request
        std::list<std::string> krb_ticket_paths;
        credentialsfetcher::CreateNonDomainJoinedKerberosLeaseRequest request;
        std::pair<std::string, std::list<std::string>> result;
        for ( std::list<std::string>::const_iterator i = credspec_contents.begin();
              i != credspec_contents.end(); ++i )
        {
            request.add_credspec_contents( i->c_str() );
        }
        request.set_username(username);
        request.set_password(password);
        request.set_domain(domain);

        credentialsfetcher::CreateNonDomainJoinedKerberosLeaseResponse response;
        grpc::ClientContext context;
        grpc::Status status;

        // Send request
        status = _stub->AddNonDomainJoinedKerberosLease( &context, request, &response );

        // Handle response
        if ( status.ok() )
        {
            for ( int i = 0; i < response.created_kerberos_file_paths_size(); i++ )
            {
                std::string msg =
                    "created ticket for non domain joined gMSA " + response.created_kerberos_file_paths( i );
                krb_ticket_paths.push_back( msg );
                std::cout << msg << std::endl;
            }
            result = std::pair<std::string, std::list<std::string>>( response.lease_id(),
                                                                     krb_ticket_paths );
        }
        else
        {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            result =
                std::pair<std::string, std::list<std::string>>( "RPC failed", krb_ticket_paths );
            return result;
        }

        return result;
    }

    /**
     * Test method to renew kerberos tickets in non domain joined mode
     * @param username - username for the AD user
     * @param password - password for the AD user
     * @param domain - domain associated to gMSA account
     * @return
     */

    std::list<std::string> RenewNonDomainJoinedKerberosLeaseMethod(std::string username, std::string password, std::string
                                                                                          domain )
    {
        // Prepare request
        std::list<std::string> krb_ticket_paths;
        credentialsfetcher::RenewNonDomainJoinedKerberosLeaseRequest request;
        request.set_username(username);
        request.set_password(password);
        request.set_domain(domain);

        credentialsfetcher::RenewNonDomainJoinedKerberosLeaseResponse response;
        grpc::ClientContext context;
        grpc::Status status;

        // Send request
        status = _stub->RenewNonDomainJoinedKerberosLease( &context, request, &response );

        // Handle response
        if ( status.ok() )
        {
            std::cout << "kerberos ticket renewal successful" <<
                 std::endl;
            for ( int i = 0; i < response.renewed_kerberos_file_paths_size(); i++ )
            {
                std::string msg =
                    "renewed ticket file " + response.renewed_kerberos_file_paths( i );
                krb_ticket_paths.push_back( msg );
                std::cout << msg << std::endl;
            }
        }
        else{
            std::cout << "Failed to renew tickets" << std::endl;
        }
        return krb_ticket_paths;
    }


    /**
     * Test method to delete kerberos tickets
     * @param credspec_contents - lease_id corresponding to the tickets created
     * @return
     */
    std::pair<std::string, std::list<std::string>> DeleteKerberosLeaseMethod( std::string lease_id )
    {
        std::pair<std::string, std::list<std::string>> result;
        std::list<std::string> krb_ticket_paths;
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
                std::string msg =
                    "deleted ticket file " + response.deleted_kerberos_file_paths( i );
                krb_ticket_paths.push_back( msg );
                std::cout << msg << std::endl;
            }
            result = std::pair<std::string, std::list<std::string>>( response.lease_id(),
                                                                     krb_ticket_paths );
            return result;
        }
        else
        {
            std::cerr << status.error_code() << ": " << status.error_message() << std::endl;
            result =
                std::pair<std::string, std::list<std::string>>( "RPC failed", krb_ticket_paths );
            return result;
        }
    }

  private:
    std::unique_ptr<credentialsfetcher::CredentialsFetcherService::Stub> _stub;
};

static void show_usage( std::string name )
{
    std::cout << "Usage: " << name << " <option(s)> SOURCES"
              << "Options:\n"
              << "\t-h,--help\t\tShow this help message\n"
              << "\t-no option\t\tcreate & delete kerberos tickets\n"
              << "\t --create \t\tcreate krb tickets for service account\n"
              << "\t --delete \t\tdelete krb tickets for a given lease_id\tprovide lease_id to be "
                 "deleted\n"
              << "\t --create_kerberos_tickets_non_domain_joined \t\t create tickets for non domain joined gMSA \tprovide"
                 " username, password, domain"
              << "\t --renew_kerberos_tickets_non_domain_joined \t\t create tickets for non domain "
                 "joined gMSA \tprovide"
                 "username, password, domain"
              << "\t --invalidargs \t\ttest with invalid args, failure scenario\n"
              << "\t --run_stress_test \t\tstress test with multiple accounts and leases\n"
              << std::endl;
}

// create kerberos tickets
std::pair<std::string, std::list<std::string>> create_krb_ticket(
    CredentialsFetcherClient& client, std::list<std::string> credspec_contents )
{
    std::pair<std::string, std::list<std::string>> add_kerberos_lease_response =
        client.AddKerberosLeaseMethod( credspec_contents );
    std::cout << "Client received output for add kerberos lease: "
              << add_kerberos_lease_response.first << std::endl;
    return add_kerberos_lease_response;
}

// create kerberos tickets non domain-joined
std::pair<std::string, std::list<std::string>> create_krb_ticket_non_domain_joined(
    CredentialsFetcherClient& client, std::list<std::string> credspec_contents,
    std::string username, std::string password, std::string domain )
{
    std::pair<std::string, std::list<std::string>> non_domain_joined_kerberos_lease_response =
        client.AddNonDomainJoinedKerberosLeaseMethod( credspec_contents, username, password,
                                                      domain );
    std::cout << "Client received output for add kerberos lease non domain joined: "
              << non_domain_joined_kerberos_lease_response.first << std::endl;
    return non_domain_joined_kerberos_lease_response;
}

// renew kerberos tickets non domain-joined
 std::list<std::string> renew_krb_ticket_non_domain_joined(
    CredentialsFetcherClient& client, std::string username,
    std::string password, std::string domain )
{
    std::list<std::string> non_domain_joined_kerberos_lease_response =
        client.RenewNonDomainJoinedKerberosLeaseMethod( username, password, domain );
    std::cout << "Client received output for renew kerberos lease non domain joined" << std::endl;
    return non_domain_joined_kerberos_lease_response;
}

// delete kerberos tickets
std::pair<std::string, std::list<std::string>> delete_krb_ticket( CredentialsFetcherClient& client,
                                                                  std::string lease_id )
{
    std::pair<std::string, std::list<std::string>> delete_kerberos_lease_response =
        client.DeleteKerberosLeaseMethod( lease_id );
    std::cout << "Client received output for delete kerberos lease: "
              << delete_kerberos_lease_response.first << std::endl;
    return delete_kerberos_lease_response;
}

int run_stress_test( CredentialsFetcherClient& client, int num_of_leases,
                     int number_of_service_acounts )
{
    // log stress test metric
    std::ofstream logfile;
    logfile.open( "stress_test_log.txt" );
    try
    {
        auto start = std::chrono::system_clock::now();
        std::time_t start_time = std::chrono::system_clock::to_time_t( start );

        logfile << "Start time: ";
        logfile << std::ctime( &start_time );
        logfile << "\n";

        std::ifstream file( "credspec_stress_test.txt" );
        if ( !file )
        {
            std::cerr << "ERROR: Cannot open 'credspec_stress_test.txt' !" << std::endl;
            return -1;
        }
        std::string line;
        std::vector<std::string> all_cred_specs;
        while ( std::getline( file, line ) )
        {
            all_cred_specs.push_back( line );
        }

        int num_of_credspecs = all_cred_specs.size();
        int num_of_service_accounts_in_lease = number_of_service_acounts;

        // build subsets of credspecs to make gRPC calls
        for ( int lease = 0; lease < num_of_leases; lease++ )
        {
            std::random_device rd;    // obtain a random number from hardware
            std::mt19937 gen( rd() ); // seed the generator
            std::uniform_int_distribution<> distr( 0, num_of_credspecs - 1 ); // define the range

            std::list<std::string> sub_set_credspecs;
            for ( int ns = 0; ns < num_of_service_accounts_in_lease; ns++ )
            {
                int index = distr( gen );
                sub_set_credspecs.push_back( all_cred_specs[index] );
            }
            std::pair<std::string, std::list<std::string>> add_kerberos_lease_response =
                create_krb_ticket( client, sub_set_credspecs );

            logfile << "create krb ticket with lease id: " + add_kerberos_lease_response.first +
                           "\n";
            for ( auto create_krb_path : add_kerberos_lease_response.second )
            {
                logfile << create_krb_path + "\n";
            }

            std::pair<std::string, std::list<std::string>> delete_kerberos_lease_response =
                delete_krb_ticket( client, add_kerberos_lease_response.first );

            for ( auto delete_krb_path : delete_kerberos_lease_response.second )
            {
                logfile << delete_krb_path + "\n";
            }

            logfile << "deleted krb tickets associated with lease id: " +
                           delete_kerberos_lease_response.first + "\n";
            logfile << "\n";
            sleep( 1 );
        }

        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t( end );
        logfile << "End time: ";
        logfile << std::ctime( &end_time );
        logfile << "\n";
        logfile << "time elapsed: " + std::to_string( elapsed_seconds.count() );
        logfile.close();
    }
    catch ( const std::exception& ex )
    {
        std::cerr << "Exception: '" << ex.what() << "'!" << std::endl;
        logfile.close();
        return -1;
    }

    return 0;
}

int main( int argc, char** argv )
{
    std::string lease_id;
    std::string username;
    std::string password;
    std::string domain;
    std::string is_renewal;
    int number_of_leases;
    int number_of_service_acounts;
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
        "\"Scope\":\"contoso.com\"},{\"Name\":\"WebApp03\",\"Scope\":\"contoso\"}]}}",
        "{\"CmsPlugins\":[\"ActiveDirectory\"],"
        "\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\","
        "\"MachineAccountName\":\"WebApp01\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\","
        "\"DnsTreeName\":\"contoso.com\",\"DnsName\":\"contoso.com\",\"NetBiosName\":\"contoso\"},"
        "\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"WebApp01\","
        "\"Scope\":\"contoso.com\"},{\"Name\":\"WebApp01\",\"Scope\":\"contoso\"}]}}" };

    std::list<std::string> invalid_credspec_contents = {
        "{\"CmsPlugins\":[\"ActiveDirectory\"],"
        "\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4217655605-3681839426-3493040985\","
        "\"MachineAccountName\":\"WebApp01\",\"Guid\":\"af602f85-d754-4eea-9fa8-fd76810485f1\","
        "\"DnsTreeName\":\"contoso.com\",\"NetBiosName\":\"contoso\"}," };

    std::list<std::string> lease_ids = {"12345", "34567", "45678"};
    // create and delete krb tickets
    if ( argc == 1 )
    {
        std::pair<std::string, std::list<std::string>> add_kerberos_lease_response =
            create_krb_ticket( client, credspec_contents );
        delete_krb_ticket( client, add_kerberos_lease_response.first );
    }

    for ( int i = 1; i < argc; ++i )
    {
        std::string arg = argv[i];
        if ( ( arg == "-h" ) || ( arg == "--help" ) )
        {
            show_usage( argv[0] );
            return 0;
        }
        else if ( arg == "--delete" )
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
        else if(arg == "--create_kerberos_tickets_non_domain_joined" ){
            if ( i + 2 < argc )
            {
                username = argv[i + 1];
                password = argv[i + 2];
                domain = argv[i + 3];
            }
            else
            {
                std::cout << "--create_kerberos_tickets_non_domain_joined option requires username, "
                             "password, domain"
                             "argument." << std::endl;
                return 0;
            }
            std::cout << "krb tickets will get created" << std::endl;
            create_krb_ticket_non_domain_joined( client, credspec_contents, username, password,
                                                 domain );
            i++;
        }
        else if(arg == "--renew_kerberos_tickets_non_domain_joined" ){
            if ( i + 2 < argc )
            {
                username = argv[i + 1];
                password = argv[i + 2];
                domain = argv[i + 3];
            }
            else
            {
                std::cout << "--renew_kerberos_tickets_non_domain_joined option requires "
                             "username, "
                             "password, domain"
                             "argument." << std::endl;
                return 0;
            }
            std::cout << "krb tickets will get renewed" << std::endl;
            renew_krb_ticket_non_domain_joined( client, username, password,
                                                 domain );
            i++;
        }
        else if ( arg == "--create" )
        {
            if ( i + 1 < argc )
            {
                std::list<std::string> credspecs = {argv[i + 1]};
                create_krb_ticket( client, credspecs );
                i++;
            }
            else
            {
                std::cout << "krb tickets will get created" << std::endl;
                create_krb_ticket( client, credspec_contents );
            }
        }
        else if ( arg == "--invalidargs" )
        {
            std::cout << "test for invalid args" << std::endl;
            create_krb_ticket( client, invalid_credspec_contents );
        }
        else if ( arg == "--run_stress_test" )
        {
            if ( i + 2 < argc )
            {
                number_of_leases = atoi( argv[i + 1] );
                number_of_service_acounts = atoi( argv[i + 2] );
            }
            else
            {
                std::cout << "--run_stress_testing option requires number_of_leases and "
                             "number_of_service_account per lease arguments. "
                          << std::endl;
                return 0;
            }
            run_stress_test( client, number_of_leases, number_of_service_acounts );
            i = 1 + 2;
        }
        else
        {
            std::cout << "provide a valid arg, for help use -h or --help" << std::endl;
            return 0;
        }
    }
    return 0;
}
