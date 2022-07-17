#include "../../common/daemon.h"

#if FEDORA_FOUND
#include <credentialsfetcher.grpc.pb.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#define UNIX_SOCKET_NAME "credentials_fetcher.sock"

/**
 * gRPC code derived from
 * https://github.com/grpc/grpc/blob/master/examples/cpp/helloworld/greeter_async_server.cc
 */
class CredentialsFetcherImpl final
{
  public:
    ~CredentialsFetcherImpl()
    {
        server_->Shutdown();
        // Always shutdown the completion queue after the server.
        cq_->Shutdown();
    }

    /**
     * RunServer - Run one grpc server for all rpcs
     * @param unix_socket_path: path to unix domain socket
     * @param cf_logger : log to systemd
     */
    void RunServer( std::string unix_socket_path, creds_fetcher::CF_logger& cf_logger )
    {
        std::string unix_socket_address =
            std::string( "unix:" ) + unix_socket_path + "/" + std::string( UNIX_SOCKET_NAME );
        std::string server_address( unix_socket_address );

        grpc::ServerBuilder builder;
        // Listen on the given address without any authentication mechanism.
        builder.AddListeningPort( server_address, grpc::InsecureServerCredentials() );
        // Register "service_" as the instance through which we'll communicate with
        // clients. In this case it corresponds to an *asynchronous* service.
        builder.RegisterService( &service_ );
        // Get hold of the completion queue used for the asynchronous communication
        // with the gRPC runtime.
        cq_ = builder.AddCompletionQueue();
        // Finally assemble the server.
        server_ = builder.BuildAndStart();
        std::cout << "Server listening on " << server_address << std::endl;

        // Proceed to the server's main loop.
        HandleRpcs();
    }

  private:
    // Class encompasing the state and logic needed to serve a request.
    class CallDataCreateKerberosLease
    {
      public:
        std::string cookie;
#define CLASS_NAME_CallDataCreateKerberosLease "CallDataCreateKerberosLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataCreateKerberosLease(
            credentialsfetcher::CredentialsFetcherService::AsyncService* service,
            grpc::ServerCompletionQueue* cq )
            : service_( service )
            , cq_( cq )
            , create_krb_responder_( &add_krb_ctx_ )
            , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataCreateKerberosLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed()
        {
            if (cookie.compare(CLASS_NAME_CallDataCreateKerberosLease) != 0) {
                    return;
            }
            printf("CallDataCreateKerberosLease %p status: %d\n", this, status_);
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestAddKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestAddKerberosLease( &add_krb_ctx_, &create_krb_request_,
                                                   &create_krb_responder_, cq_, cq_,
                                                   this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataCreateKerberosLease( service_, cq_ );

                // The actual processing.
                create_krb_reply_.set_lease_id( "12345" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                create_krb_responder_.Finish( create_krb_reply_, grpc::Status::OK,
                                              this );
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }

      private:
        // The means of communication with the gRPC runtime for an asynchronous
        // server.
        credentialsfetcher::CredentialsFetcherService::AsyncService* service_;
        // The producer-consumer queue where for asynchronous server notifications.
        grpc::ServerCompletionQueue* cq_;
        // Context for the rpc, allowing to tweak aspects of it such as the use
        // of compression, authentication, as well as to send metadata back to the
        // client.
        grpc::ServerContext add_krb_ctx_;

        // What we get from the client.
        credentialsfetcher::CreateKerberosLeaseRequest create_krb_request_;
        // What we send back to the client.
        credentialsfetcher::CreateKerberosLeaseResponse create_krb_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher::CreateKerberosLeaseResponse>
            create_krb_responder_;

        // Let's implement a tiny state machine with the following states.
        enum CallStatus
        {
            CREATE,
            PROCESS,
            FINISH
        };
        CallStatus status_; // The current serving state.
    };

    // Class encompasing the state and logic needed to serve a request.
    class CallDataDeleteKerberosLease
    {
      public:
        std::string cookie;
#define CLASS_NAME_CallDataDeleteKerberosLease "CallDataDeleteKerberosLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataDeleteKerberosLease(
            credentialsfetcher::CredentialsFetcherService::AsyncService* service,
            grpc::ServerCompletionQueue* cq )
            : service_( service )
            , cq_( cq )
            , delete_krb_responder_( &del_krb_ctx_ )
            , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataDeleteKerberosLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed()
        {
            if (cookie.compare(CLASS_NAME_CallDataDeleteKerberosLease) != 0) {
                    return;
            }
            printf("CallDataDeleteKerberosLease %p status: %d\n", this, status_);
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestAddKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestDeleteKerberosLease( &del_krb_ctx_, &delete_krb_request_,
                                                      &delete_krb_responder_, cq_, cq_,
                                                      this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataDeleteKerberosLease( service_, cq_ );

                // The actual processing.
                delete_krb_reply_.set_lease_id( "12345" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                delete_krb_responder_.Finish( delete_krb_reply_, grpc::Status::OK,
                                              this );
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }
      private:
        // The means of communication with the gRPC runtime for an asynchronous
        // server.
        credentialsfetcher::CredentialsFetcherService::AsyncService* service_;
        // The producer-consumer queue where for asynchronous server notifications.
        grpc::ServerCompletionQueue* cq_;
        // Context for the rpc, allowing to tweak aspects of it such as the use
        // of compression, authentication, as well as to send metadata back to the
        // client.
        grpc::ServerContext del_krb_ctx_;

        // What we get from the client.
        credentialsfetcher::DeleteKerberosLeaseRequest delete_krb_request_;
        // What we send back to the client.
        credentialsfetcher::DeleteKerberosLeaseResponse delete_krb_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher::DeleteKerberosLeaseResponse>
            delete_krb_responder_;

        // Let's implement a tiny state machine with the following states.
        enum CallStatus
        {
            CREATE,
            PROCESS,
            FINISH
        };
        CallStatus status_; // The current serving state.
    };

    // This can be run in multiple threads if needed.
    void HandleRpcs()
    {
        void* got_tag; // uniquely identifies a request.
        bool ok;

        new CallDataCreateKerberosLease( &service_, cq_.get() );
        new CallDataDeleteKerberosLease( &service_, cq_.get() );

        while ( true ) // TBD:: add shutdown flag
        {
            // Spawn a new CallData instance to serve new clients.
            // Block waiting to read the next event from the completion queue. The
            // event is uniquely identified by its tag, which in this case is the
            // memory address of a CallData instance.
            // The return value of Next should always be checked. This return value
            // tells us whether there is any kind of event or cq_ is shutting down.
            GPR_ASSERT( cq_->Next( &got_tag, &ok ) );
            GPR_ASSERT( ok );

            static_cast<CallDataCreateKerberosLease*>(got_tag)->Proceed();
            static_cast<CallDataDeleteKerberosLease*>(got_tag)->Proceed();
        }
    }

    std::unique_ptr<grpc::ServerCompletionQueue> cq_;
    credentialsfetcher::CredentialsFetcherService::AsyncService service_;
    std::unique_ptr<grpc::Server> server_;
};

/**
 * RunGrpcServer - Runs the grpc initializes and runs the grpc server
 * @param unix_socket_path - path for the unix socket creation
 * @param cf_logger - log to systemd daemon
 * @return - return 0 when server exits
 */
int RunGrpcServer( std::string unix_socket_path, creds_fetcher::CF_logger& cf_logger )
{
    CredentialsFetcherImpl creds_fetcher_grpc;

    creds_fetcher_grpc.RunServer( unix_socket_path, cf_logger );

    // TBD:: Add return status for errors
    return 0;
}
#endif
