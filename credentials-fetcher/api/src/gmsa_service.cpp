#include "../../common/daemon.h"

#if FEDORA_FOUND
#include <credentialsfetcher.grpc.pb.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#define unix_socket_name "credentials_fetcher.sock"

/**
 * CredentialsFetcherServiceImpl - Credentials fetcher implementation for the grpc service
 */
class CredentialsFetcherServiceImpl final
    : public credentialsfetcher::CredentialsFetcherService::Service
{
    /**
     * Method to create kerberos ticket for the service accounts
     * @param context - context
     * @param request - kerberos ticket creation request - list of credential spec contents
     * @param response - kerberos ticket creation response - lease_id and krb_ticket_paths for the
     * tickets created
     * @return
     */
    grpc::Status AddKerberosLease(
        grpc::ServerContext* context, const credentialsfetcher::CreateKerberosLeaseRequest* request,
        credentialsfetcher::CreateKerberosLeaseResponse* response ) override
    {
        std::cout << "Kerberos tickets got created" << std::endl;
        response->set_lease_id( "12345" );
        return grpc::Status::OK;
    }

    /**
     * Method to delete kerberos ticket for the service accounts
     * @param context - context
     * @param request - kerberos ticket deletion request - lease_id associated with krb tickets
     * created
     * @param response - kerberos ticket deletion response - lease_id and krb_ticket_paths for the
     * tickets deleted
     * @return
     */
    grpc::Status DeleteKerberosLease(
        grpc::ServerContext* context, const credentialsfetcher::DeleteKerberosLeaseRequest* request,
        credentialsfetcher::DeleteKerberosLeaseResponse* response ) override
    {
        std::cout << "Kerberos tickets got deleted" << std::endl;
        response->set_lease_id( "12345" );
        return grpc::Status::OK;
    }
};
#endif

/**
 * RunGrpcServer - Runs the grpc initializes and runs the grpc server
 * @param unix_socket_path - path for the unix socket creation
 * @param cf_logger - log to systemd daemon
 * @return
 */
int RunGrpcServer( std::string unix_socket_path, creds_fetcher::CF_logger& cf_logger )
{
#if FEDORA_FOUND
    std::string unix_socket_address = "unix:" + unix_socket_path + "/" + unix_socket_name;
    std::string server_address( unix_socket_address );
    CredentialsFetcherServiceImpl service;
    grpc::EnableDefaultHealthCheckService( true );
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
    grpc::ServerBuilder builder;

    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort( server_address, grpc::InsecureServerCredentials() );
    // Register "service" as the instance through which we'll communicate with the clients.
    builder.RegisterService( &service );

    std::unique_ptr<grpc::Server> server( builder.BuildAndStart() );
    std::cout << "Server listening on " << server_address << std::endl;

    server->Wait();
#else
    std::cout << "grpc support for gmsa is not available on the operating system" << std::endl;
#endif
    return 0;
}