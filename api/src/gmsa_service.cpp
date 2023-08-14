#include "daemon.h"

#include <boost/filesystem.hpp>
#include <credentialsfetcher.grpc.pb.h>
#include <fstream>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <random>

#define LEASE_ID_LENGTH 10
#define UNIX_SOCKET_NAME "credentials_fetcher.sock"
#define INPUT_CREDENTIALS_LENGTH 256

static const std::vector<char> invalid_characters = {
    '&', '|', ';', '$', '*', '?', '<', '>', '!',' '};


/**
 *
 * @param value - string input that has to be validated
 * @return true or false if string contains or not contains invalid characters
 */
bool contains_invalid_characters_in_credentials( const std::string& value )
{
    bool result = false;
    // Iterate over all characters in invalid_path_characters vector
    for ( const char& ch : invalid_characters )
    {
        // Check if character exist in string
        if ( value.find( ch ) != std::string::npos )
        {
            result = true;
            break;
        }
    }
    return result;
}

volatile sig_atomic_t* pthread_shutdown_signal = nullptr;

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
     * @param unix_socket_dir: path to unix domain socket
     * @param cf_logger : log to systemd
     */
    void RunServer( std::string unix_socket_dir, std::string krb_files_dir,
                    creds_fetcher::CF_logger& cf_logger, std::string aws_sm_secret_name )
    {
        std::string unix_socket_address =
            std::string( "unix:" ) + unix_socket_dir + "/" + std::string( UNIX_SOCKET_NAME );
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
        HandleRpcs( krb_files_dir, cf_logger, aws_sm_secret_name );
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

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataCreateKerberosLease ) != 0 )
            {
                return;
            }

            printf( "CallDataCreateKerberosLease %p status: %d\n", this, status_ );
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
                                                   &create_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataCreateKerberosLease( service_, cq_ );
                // The actual processing.
                std::string lease_id = generate_lease_id();
                std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list;
                std::unordered_set<std::string> krb_ticket_dirs;

                std::string err_msg;
                create_krb_reply_.set_lease_id( lease_id );
                for ( int i = 0; i < create_krb_request_.credspec_contents_size(); i++ )
                {
                    creds_fetcher::krb_ticket_info* krb_ticket_info =
                        new creds_fetcher::krb_ticket_info;
                    int parse_result = parse_cred_spec( create_krb_request_.credspec_contents( i ),
                                                        krb_ticket_info, false );

                    // only add the ticket info if the parsing is successful
                    if ( parse_result == 0 )
                    {
                        std::string krb_files_path = krb_files_dir + "/" + lease_id + "/" +
                                                     krb_ticket_info->service_account_name;
                        krb_ticket_info->krb_file_path = krb_files_path;
                        krb_ticket_info->domainless_user = "";

                        // handle duplicate service accounts
                        if ( !krb_ticket_dirs.count( krb_files_path ) )
                        {
                            krb_ticket_dirs.insert( krb_files_path );
                            krb_ticket_info_list.push_back( krb_ticket_info );
                        }
                    }
                    else
                    {
                        err_msg = "Error: credential spec provided is not properly formatted";
                        break;
                    }
                }
                if ( err_msg.empty() )
                {
                    // create the kerberos tickets for the service accounts
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        // invoke to get machine ticket
                        int status = 0;
                        if ( aws_sm_secret_name.length() != 0 )
                        {
                            status = get_user_krb_ticket( krb_ticket->domain_name,
                                                          aws_sm_secret_name, cf_logger );
                            krb_ticket->domainless_user =
                                "awsdomainlessusersecret:"+aws_sm_secret_name;
                        }
                        else
                        {
                            status = get_machine_krb_ticket( krb_ticket->domain_name, cf_logger );
                        }
                        if ( status < 0 )
                        {
                            cf_logger.logger( LOG_ERR, "Error %d: Cannot get machine krb ticket",
                                              status );
                            err_msg = "ERROR: cannot get machine krb ticket";
                            break;
                        }

                        std::string krb_file_path = krb_ticket->krb_file_path;
                        if ( boost::filesystem::exists( krb_file_path ) )
                        {
                            cf_logger.logger( LOG_INFO,
                                              "Directory already exists: "
                                              "%s",
                                              krb_file_path );
                            break;
                        }
                        boost::filesystem::create_directories( krb_file_path );

                        std::string krb_ccname_str = krb_ticket->krb_file_path + "/krb5cc";

                        if ( !boost::filesystem::exists( krb_ccname_str ) )
                        {
                            std::ofstream file( krb_ccname_str );
                            file.close();

                            krb_ticket->krb_file_path = krb_ccname_str;
                        }

                        std::pair<int, std::string> gmsa_ticket_result = get_gmsa_krb_ticket(
                            krb_ticket->domain_name, krb_ticket->service_account_name,
                            krb_ccname_str, cf_logger );
                        if ( gmsa_ticket_result.first != 0 )
                        {
                            err_msg = "ERROR: Cannot get gMSA krb ticket";
                            std::cout << err_msg << std::endl;
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                              status );
                            break;
                        }
                        else
                        {
                            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                              gmsa_ticket_result.second );
                            std::cout << "gMSA ticket is at " << gmsa_ticket_result.second
                                      << std::endl;
                        }
                        create_krb_reply_.add_created_kerberos_file_paths( krb_file_path );
                    }
                }
                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() )
                {
                    // remove the directories on failure
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        boost::filesystem::remove_all( krb_ticket->krb_file_path );
                    }
                    status_ = FINISH;
                    create_krb_responder_.Finish(
                        create_krb_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                        this );
                }
                else
                {
                    // write the ticket information to meta data file
                    write_meta_data_json( krb_ticket_info_list, lease_id, krb_files_dir );
                    status_ = FINISH;
                    create_krb_responder_.Finish( create_krb_reply_, grpc::Status::OK, this );
                }
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }

        void Proceed()
        {
            if ( cookie.compare( CLASS_NAME_CallDataCreateKerberosLease ) != 0 )
            {
                return;
            }
            printf( "CallDataCreateKerberosLease %p status: %d\n", this, status_ );
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
                                                   &create_krb_responder_, cq_, cq_, this );
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
                create_krb_responder_.Finish( create_krb_reply_, grpc::Status::OK, this );
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
    class CallDataAddNonDomainJoinedKerberosLease
    {
      public:
        std::string cookie;
#define CLASS_NAME_CallDataAddNonDomainJoinedKerberosLease \
    "CallDataAddNonDomainJoinedKerberosLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataAddNonDomainJoinedKerberosLease(
            credentialsfetcher::CredentialsFetcherService::AsyncService* service,
            grpc::ServerCompletionQueue* cq )
            : service_( service )
            , cq_( cq )
            , handle_krb_responder_( &add_krb_ctx_ )
            , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataAddNonDomainJoinedKerberosLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataAddNonDomainJoinedKerberosLease ) != 0 )
            {
                return;
            }

            printf( "AddNonDomainJoinedKerberosLease %p status: %d\n", this, status_ );
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestAddNonDomainJoinedKerberosLease( &add_krb_ctx_,
                                                                 &create_domainless_krb_request_,
                                                   &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataAddNonDomainJoinedKerberosLease(service_, cq_ );
                // The actual processing.
                std::string lease_id = generate_lease_id();
                std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list;
                std::unordered_set<std::string> krb_ticket_dirs;
                std::string username = create_domainless_krb_request_.username();
                std::string password = create_domainless_krb_request_.password();
                std::string domain = create_domainless_krb_request_.domain();

                std::string err_msg;
                if(!contains_invalid_characters_in_credentials(domain))
                {
                    if ( !username.empty() && !password.empty() && !domain.empty() && username.length() < INPUT_CREDENTIALS_LENGTH && password.length() <
                                                                                                                                          INPUT_CREDENTIALS_LENGTH )
                       {
                        create_domainless_krb_reply_.set_lease_id( lease_id );
                        for ( int i = 0;
                              i < create_domainless_krb_request_.credspec_contents_size(); i++ )
                        {
                            creds_fetcher::krb_ticket_info* krb_ticket_info =
                                new creds_fetcher::krb_ticket_info;
                            int parse_result = parse_cred_spec(
                                create_domainless_krb_request_.credspec_contents( i ),
                                krb_ticket_info, false );

                            // only add the ticket info if the parsing is successful
                            if ( parse_result == 0 )
                            {
                                std::string krb_files_path = krb_files_dir + "/" + lease_id + "/" +
                                                             krb_ticket_info->service_account_name;
                                krb_ticket_info->krb_file_path = krb_files_path;
                                krb_ticket_info->domainless_user = username;

                                // handle duplicate service accounts
                                if ( !krb_ticket_dirs.count( krb_files_path ) )
                                {
                                    krb_ticket_dirs.insert( krb_files_path );
                                    krb_ticket_info_list.push_back( krb_ticket_info );
                                }
                            }
                            else
                            {
                                err_msg = "Error: credential spec provided is not properly "
                                          "formatted";
                                break;
                            }
                        }
                    }
                    else
                    {
                        err_msg = "Error: domainless AD user credentials is not valid/ "
                                  "credentials should not be more than 256 charaters";
                    }
                }
                else
                {
                   err_msg = "Error: invalid domainName";
                }
                if ( err_msg.empty() )
                {
                    // create the kerberos tickets for the service accounts
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        // invoke to get machine ticket
                        int status = 0;
                        if ( username.empty()  ||  password.empty() )
                        {
                            cf_logger.logger( LOG_ERR, "Invalid credentials for "
                                                       "domainless user ");
                            err_msg = "ERROR: Invalid credentials for mainless user";
                            break;
                        }
                        status = get_domainless_user_krb_ticket( domain,
                                                                 username, password,
                                                                     cf_logger );
                        if ( status < 0 )
                        {
                            cf_logger.logger( LOG_ERR, "Error %d: cannot domainless user kerberos tickets",
                                              status );
                            err_msg = "ERROR: cannot domainless user kerberos tickets";
                            break;
                        }

                        std::string krb_file_path = krb_ticket->krb_file_path;
                        if ( boost::filesystem::exists( krb_file_path ) )
                        {
                            cf_logger.logger( LOG_INFO,
                                              "Directory already exists: "
                                              "%s",
                                              krb_file_path );
                            break;
                        }
                        boost::filesystem::create_directories( krb_file_path );

                        std::string krb_ccname_str = krb_ticket->krb_file_path + "/krb5cc";

                        if ( !boost::filesystem::exists( krb_ccname_str ) )
                        {
                            std::ofstream file( krb_ccname_str );
                            file.close();

                            krb_ticket->krb_file_path = krb_ccname_str;
                        }

                        std::pair<int, std::string> gmsa_ticket_result = get_gmsa_krb_ticket(
                            domain, krb_ticket->service_account_name,
                            krb_ccname_str, cf_logger );
                        if ( gmsa_ticket_result.first != 0 )
                        {
                            err_msg = "ERROR: Cannot get gMSA krb ticket";
                            std::cout << err_msg << std::endl;
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                              status );
                            break;
                        }
                        else
                        {
                            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                              gmsa_ticket_result.second );
                            std::cout << "gMSA ticket is at " << gmsa_ticket_result.second
                                      << std::endl;
                        }
                        create_domainless_krb_reply_.add_created_kerberos_file_paths( krb_file_path );
                    }
                }
                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() )
                {
                    username = "xxxx";
                    password = "xxxx";
                    // remove the directories on failure
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        boost::filesystem::remove_all( krb_ticket->krb_file_path );
                    }
                    status_ = FINISH;
                    handle_krb_responder_.Finish(
                        create_domainless_krb_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                        this );
                }
                else
                {
                    username = "xxxx";
                    password = "xxxx";
                    // write the ticket information to meta data file
                    write_meta_data_json( krb_ticket_info_list, lease_id, krb_files_dir );
                    status_ = FINISH;
                    handle_krb_responder_.Finish( create_domainless_krb_reply_, grpc::Status::OK,
                                                             this );
                }
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }

        void Proceed()
        {
            if ( cookie.compare( CLASS_NAME_CallDataAddNonDomainJoinedKerberosLease ) != 0 )
            {
                return;
            }
            printf( "AddNonDomainJoinedKerberosLease %p status: %d\n", this, status_ );
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestAddNonDomainJoinedKerberosLease( &add_krb_ctx_,
                                                                 &create_domainless_krb_request_,
                                                   &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataAddNonDomainJoinedKerberosLease(service_, cq_ );
                // The actual processing.
                create_domainless_krb_reply_.set_lease_id( "12345" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                handle_krb_responder_.Finish( create_domainless_krb_reply_, grpc::Status::OK,
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
        credentialsfetcher::CreateNonDomainJoinedKerberosLeaseRequest
            create_domainless_krb_request_;
        // What we send back to the client.
        credentialsfetcher::CreateNonDomainJoinedKerberosLeaseResponse create_domainless_krb_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher
                                        ::CreateNonDomainJoinedKerberosLeaseResponse>
            handle_krb_responder_;

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
    class CallDataRenewNonDomainJoinedKerberosLease
    {
      public:
        std::string cookie;
#define CLASS_NAME_CallDataRenewNonDomainJoinedKerberosLease \
    "CallDataRenewNonDomainJoinedKerberosLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataRenewNonDomainJoinedKerberosLease(
            credentialsfetcher::CredentialsFetcherService::AsyncService* service,
            grpc::ServerCompletionQueue* cq )
            : service_( service )
            , cq_( cq )
            , handle_krb_responder_( &add_krb_ctx_ )
            , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataRenewNonDomainJoinedKerberosLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataRenewNonDomainJoinedKerberosLease ) != 0 )
            {
                return;
            }

            printf( "RenewNonDomainJoinedKerberosLease %p status: %d\n", this, status_ );
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestRenewNonDomainJoinedKerberosLease( &add_krb_ctx_,
                                                                  &renew_domainless_krb_request_,
                                                                  &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataRenewNonDomainJoinedKerberosLease( service_, cq_ );
                // The actual processing.
                std::string lease_id = generate_lease_id();
                std::string username = renew_domainless_krb_request_.username();
                std::string password = renew_domainless_krb_request_.password();
                std::string domain = renew_domainless_krb_request_.domain();

                std::string err_msg;
                if(!contains_invalid_characters_in_credentials(domain))
                {
                    if ( !username.empty() && !password.empty() && !domain.empty() && username.length() < INPUT_CREDENTIALS_LENGTH && password.length() <
                                                                                                                                          INPUT_CREDENTIALS_LENGTH )
                    {
                        std::list<std::string> renewed_krb_file_paths =
                            renew_kerberos_tickets_domainless( krb_files_dir, domain, username,
                                                               password, cf_logger );

                        for ( auto renewed_krb_path : renewed_krb_file_paths )
                        {
                            renew_domainless_krb_reply_.add_renewed_kerberos_file_paths(
                                renewed_krb_path );
                        }
                    }
                    else
                    {
                        err_msg = "Error: domainless AD user credentials is not valid/ "
                                  "credentials should not be more than 256 charaters";
                    }
                }
                else
                {
                    err_msg = "Error: invalid domainName";
                }

                username = "xxxx";
                password = "xxxx";

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() )
                {
                    status_ = FINISH;
                    handle_krb_responder_.Finish(
                        renew_domainless_krb_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                        this );
                }
                else
                {
                    status_ = FINISH;
                    handle_krb_responder_.Finish( renew_domainless_krb_reply_, grpc::Status::OK, this );
                }
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }

        void Proceed()
        {
            if ( cookie.compare( CLASS_NAME_CallDataRenewNonDomainJoinedKerberosLease ) != 0 )
            {
                return;
            }
            printf( "RenewNonDomainJoinedKerberosLease %p status: %d\n", this, status_ );
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestRenewNonDomainJoinedKerberosLease( &add_krb_ctx_,
                                                                    &renew_domainless_krb_request_,
                                                                    &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataRenewNonDomainJoinedKerberosLease(service_, cq_ );
                // The actual processing.
                renew_domainless_krb_reply_.add_renewed_kerberos_file_paths(
                    "/var/credentials-fetcher/krb5cc" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                handle_krb_responder_.Finish( renew_domainless_krb_reply_, grpc::Status::OK,
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
        credentialsfetcher::RenewNonDomainJoinedKerberosLeaseRequest
            renew_domainless_krb_request_;
        // What we send back to the client.
        credentialsfetcher::RenewNonDomainJoinedKerberosLeaseResponse renew_domainless_krb_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher
                                        ::RenewNonDomainJoinedKerberosLeaseResponse>
            handle_krb_responder_;

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
        std::string aws_sm_secret_name;

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

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataDeleteKerberosLease ) != 0 )
            {
                return;
            }
            printf( "CallDataDeleteKerberosLease %p status: %d\n", this, status_ );
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
                                                      &delete_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataDeleteKerberosLease( service_, cq_ );

                // The actual processing.
                std::string lease_id = delete_krb_request_.lease_id();
                std::string err_msg;

                if ( !lease_id.empty() )
                {
                    std::vector<std::string> deleted_krb_file_paths =
                        delete_krb_tickets( krb_files_dir, lease_id );

                    for ( auto deleted_krb_path : deleted_krb_file_paths )
                    {
                        delete_krb_reply_.add_deleted_kerberos_file_paths( deleted_krb_path );
                    }
                    delete_krb_reply_.set_lease_id( lease_id );
                }
                else
                {
                    err_msg = "Error: lease_id is not valid";
                }

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() )
                {
                    status_ = FINISH;
                    delete_krb_responder_.Finish(
                        delete_krb_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                        this );
                }
                else
                {
                    status_ = FINISH;
                    delete_krb_responder_.Finish( delete_krb_reply_, grpc::Status::OK, this );
                }
            }
            else
            {
                GPR_ASSERT( status_ == FINISH );
                // Once in the FINISH state, deallocate ourselves (CallData).
                delete this;
            }

            return;
        }
        void Proceed()
        {
            if ( cookie.compare( CLASS_NAME_CallDataDeleteKerberosLease ) != 0 )
            {
                return;
            }
            printf( "CallDataDeleteKerberosLease %p status: %d\n", this, status_ );
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
                                                      &delete_krb_responder_, cq_, cq_, this );
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
                delete_krb_responder_.Finish( delete_krb_reply_, grpc::Status::OK, this );
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
    void HandleRpcs( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                     std::string aws_sm_secret_name )
    {
        void* got_tag; // uniquely identifies a request.
        bool ok;

        new CallDataCreateKerberosLease( &service_, cq_.get() );
        new CallDataAddNonDomainJoinedKerberosLease ( &service_, cq_.get() );
        new CallDataRenewNonDomainJoinedKerberosLease ( &service_, cq_.get() );
        new CallDataDeleteKerberosLease( &service_, cq_.get() );

        while ( pthread_shutdown_signal != nullptr && !( *pthread_shutdown_signal ) )
        {
            // Spawn a new CallData instance to serve new clients.
            // Block waiting to read the next event from the completion queue. The
            // event is uniquely identified by its tag, which in this case is the
            // memory address of a CallData instance.
            // The return value of Next should always be checked. This return value
            // tells us whether there is any kind of event or cq_ is shutting down.
            GPR_ASSERT( cq_->Next( &got_tag, &ok ) );
            GPR_ASSERT( ok );

            static_cast<CallDataCreateKerberosLease*>( got_tag )->Proceed( krb_files_dir, cf_logger,
                                                                           aws_sm_secret_name );
            static_cast<CallDataAddNonDomainJoinedKerberosLease*>( got_tag )->Proceed(
                krb_files_dir, cf_logger,
                                                                           aws_sm_secret_name );
            static_cast<CallDataRenewNonDomainJoinedKerberosLease*>( got_tag )->Proceed(
                krb_files_dir, cf_logger,
                aws_sm_secret_name );
            static_cast<CallDataDeleteKerberosLease*>( got_tag )->Proceed( krb_files_dir, cf_logger,
                                                                           aws_sm_secret_name );
        }
    }

    std::unique_ptr<grpc::ServerCompletionQueue> cq_;
    credentialsfetcher::CredentialsFetcherService::AsyncService service_;
    std::unique_ptr<grpc::Server> server_;
};

/**
 * RunGrpcServer - Runs the grpc initializes and runs the grpc server
 * @param unix_socket_dir - path for the unix socket creation
 * @param cf_logger - log to systemd daemon
 * @param shutdown_signal - sigterm from systemd
 * @return - return 0 when server exits
 */
int RunGrpcServer( std::string unix_socket_dir, std::string krb_files_dir,
                   creds_fetcher::CF_logger& cf_logger, volatile sig_atomic_t* shutdown_signal,
                   std::string aws_sm_secret_name )
{
    CredentialsFetcherImpl creds_fetcher_grpc;

    pthread_shutdown_signal = shutdown_signal;

    creds_fetcher_grpc.RunServer( unix_socket_dir, krb_files_dir, cf_logger, aws_sm_secret_name );

    // TBD:: Add return status for errors
    return 0;
}

/**
 * Generate a random lease_id of defined length
 * @return - string
 */
std::string generate_lease_id()
{
    std::stringstream lease_id;
    for ( auto i = 0; i < LEASE_ID_LENGTH; i++ )
    {
        // generate random character 0 to 255
        std::random_device rd;
        std::mt19937 gen( rd() );
        std::uniform_int_distribution<> dis( 0, 255 );
        auto rc = static_cast<unsigned char>( dis( gen ) );

        // build the hexstream
        std::stringstream hexstream;
        hexstream << std::hex << int( rc );
        auto hex = hexstream.str();
        lease_id << ( hex.length() < 2 ? '0' + hex : hex );
    }
    return lease_id.str();
}

/**
 * This function parses the cred spec file.
 * The cred spec file is in json format.
 * @param credspec - service account information
 * @param krb_ticket_info - return service account info
 * @return
 */
int parse_cred_spec( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info,
                     bool is_file )
{
    try
    {
        if ( credspec_data.empty() )
        {
            fprintf( stderr, SD_CRIT "credspec is empty" );
            return -1;
        }

        namespace pt = boost::property_tree;
        pt::ptree root;
        if(!is_file)
        {
            std::istringstream credspec_stream( credspec_data );
            pt::read_json( credspec_stream, root );
        }
        else{
            pt::read_json( credspec_data, root );
        }

        // get domain name from credspec
        std::string domain_name = root.get<std::string>( "DomainJoinConfig.DnsName" );
        // get service account name from credspec
        std::string service_account_name;
        const pt::ptree& child_tree_gmsa =
            root.get_child( "ActiveDirectoryConfig.GroupManagedServiceAccounts" );
        for ( const auto& kv : child_tree_gmsa )
        {
            service_account_name = kv.second.get<std::string>( "Name" );

            if ( !service_account_name.empty() )
                break;
        }

        if ( service_account_name.empty() || domain_name.empty() )
            return -1;

        krb_ticket_info->domain_name = domain_name;
        krb_ticket_info->service_account_name = service_account_name;
    }
    catch ( ... )
    {
        fprintf( stderr, SD_CRIT "credspec is not properly formatted" );
        return -1;
    }

    return 0;
}

/** All kubernetes gMSA support work **/
/**
 * * This function parses the input kube config file and modifies it.
 * The cred spec file is in json format.
 * @param kubeconfigpath - path to kubeconfig file
 * @param krb_ticket_info - return service account info
 * @return
*/
std::list<creds_fetcher::kube_config_info*> parse_kube_config( std::string kubeFilePath,
                                                                          std::string krbdir )
{
    std::list<creds_fetcher::kube_config_info*> kube_config_info_list;
    std::list<creds_fetcher::kube_meta_mapping*> kube_meta_mapping_list;
    std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list;
    std::string metadata_file_path;
    try
    {
        if ( kubeFilePath.empty() )
        {
            fprintf( stderr, SD_CRIT "kube file is empty" );
            return kube_config_info_list;
        }

        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        std::ifstream credspec_stream( kubeFilePath );

        std::string errors;

        bool parsingSuccessful = Json::parseFromStream(rbuilder, credspec_stream, &root, &errors);

        if (!parsingSuccessful) {
            std::cout << "Failed to parse the JSON, errors:" << std::endl;
            std::cout << errors << std::endl;
            return kube_config_info_list;
        }

        std::string lease_id = generate_lease_id();
        std::string meta_file_name = lease_id + "_kube_metadata.json";
        metadata_file_path = krbdir + "/" + lease_id + "/" + meta_file_name;

        Json::Value &array1 = root["ServiceAccountMappings"];
        for (int i = 0; i < (int)array1.size(); i++)
        {
            creds_fetcher::kube_config_info* kube_config_info = new creds_fetcher::kube_config_info;
            creds_fetcher::krb_ticket_info* krb_ticket_info = new creds_fetcher::krb_ticket_info;
            std::string credentialspecpath = array1[i]["path_to_cred_spec_json"].asString();
            int status = parse_cred_spec( credentialspecpath, krb_ticket_info, true );
            if ( status != -1 )
            {
                if ( krb_ticket_info->krb_file_path.empty())
                {
                    std::string ticket_path = krbdir + "/" + lease_id + "/" +
                                              krb_ticket_info->service_account_name;

                    //create ticket paths
                    krb_ticket_info->krb_file_path = ticket_path;
                    boost::filesystem::create_directories( ticket_path );
                }
                std::string domainlessUser = array1[i]["domainless_user"].asString();
                if(domainlessUser.length() != 0 )
                {
                    krb_ticket_info->domainless_user =
                       "kubedomainlessusersecret:"+domainlessUser;
                }
                else{
                    krb_ticket_info->domainless_user = "kubehostprincipal" ;
                }
            }
            kube_config_info->krb_ticket_info = krb_ticket_info;

            creds_fetcher::kube_meta_mapping* kube_meta_mapping  = new creds_fetcher::kube_meta_mapping;;
            std::list<std::string> secret_yaml_paths;
            Json::Value& array2 = array1[i]["kube_context"];
            for ( int j = 0; j < (int)array2.size(); j++ )
            {
                std::string secret_yaml_path = array2[i]["path_to_kube_secret_yaml_file"].asString();
                secret_yaml_paths.push_back( secret_yaml_path );
            }

            if(!kube_config_info->secret_yaml_map.count(kube_config_info->krb_ticket_info->krb_file_path))
            {
                kube_config_info->secret_yaml_map[kube_config_info->krb_ticket_info->krb_file_path]
                    = secret_yaml_paths;
            }
            kube_meta_mapping->secret_yaml_paths = secret_yaml_paths;
            kube_meta_mapping->krb_file_path =  krb_ticket_info->krb_file_path;
            kube_config_info->secret_yaml_paths = secret_yaml_paths;
            kube_config_info_list.push_back( kube_config_info );
            kube_meta_mapping_list.push_back(kube_meta_mapping);
            krb_ticket_info_list.push_back( krb_ticket_info );
        }

        write_meta_data_json(krb_ticket_info_list, lease_id,krbdir);
        writeKubeJsonCache(metadata_file_path,kube_meta_mapping_list);
    }
    catch ( ... )
    {
        fprintf( stderr, SD_CRIT "kubeconfig file is not properly formatted" );
        return kube_config_info_list;
    }
    return kube_config_info_list;
}

void writeKubeJsonCache(std::string metadataFilePath, std::list<creds_fetcher::kube_meta_mapping*>
    kubeMappings){
    try
    {
        // create the meta file in the lease directory
        Json::StreamWriterBuilder wbuilder;
        wbuilder["commentStyle"] = "None";
        wbuilder["indentation"] = "";
        std::unique_ptr<Json::StreamWriter> writer( wbuilder.newStreamWriter() );

        Json::Value root;
        for ( const auto& mapping : kubeMappings )
        {
            Json::Value child;
            Json::Value vec( Json::arrayValue );
            for ( const auto& path : mapping->secret_yaml_paths )
            {
                vec.append( Json::Value( path ) );
            }
            child["path_to_kube_secret_yaml"] = vec;

            child["krb_ticket_path"] = mapping->krb_file_path;
            root.append( child );
        }

        std::ofstream outputFileStream( metadataFilePath );
        writer->write( root, &outputFileStream );
    }
    catch ( ... )
    {
        fprintf( stderr, SD_CRIT "write to kube mapping failed " );
    }
}
