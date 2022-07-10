#include "../../common/daemon.h"
#include <memory>
#include <string>


#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include "../../build/api/credentialsfetcher.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using credentialsfetcher::CreateKerberosLeaseRequest;
using credentialsfetcher::CreateKerberosLeaseResponse;
using credentialsfetcher::DeleteKerberosLeaseRequest;
using credentialsfetcher::DeleteKerberosLeaseResponse;
using credentialsfetcher::CredentialsFetcherService;



/* CredentialsFetcherServiceImpl - Credentials fetcher implementation for the grpc service */
class CredentialsFetcherServiceImpl final : public CredentialsFetcherService::Service {
        Status AddKerberosLease(ServerContext* context, const CreateKerberosLeaseRequest* request,
	            CreateKerberosLeaseResponse* reply) override {
	         std::string prefix("Hello ");
	         reply->set_lease_id(prefix + "world");
	         return Status::OK;
	    }

	    Status DeleteKerberosLease(ServerContext* context, const DeleteKerberosLeaseRequest* request,
	                DeleteKerberosLeaseResponse* reply) override {
	             std::string prefix("Hello ");
	             reply->set_lease_id(prefix + request->lease_id());
	             return Status::OK;
	    }
};

/* RunGrpcServer - Runs the grpc initializes and runs the grpc server */
int RunGrpcServer() {

        std::string server_address("unix:/tmp/credentials_fetcher.sock");
	    CredentialsFetcherServiceImpl service;
	    grpc::EnableDefaultHealthCheckService(true);
	    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
	    ServerBuilder builder;

	    // Listen on the given address without any authentication mechanism.
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
	    // Register "service" as the instance through which we'll communicate with the clients.
	    builder.RegisterService(&service);

	    std::unique_ptr<Server> server(builder.BuildAndStart());
	    std::cout << "Server listening on " << server_address << std::endl;

	    server->Wait();
    return 0;
}