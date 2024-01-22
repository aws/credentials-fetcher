#include "daemon.h"

#include <iostream>
#include <credentialsfetcher.grpc.pb.h>
#include <fstream>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <random>
#include <sys/stat.h>
#include <regex>

#if AMAZON_LINUX_DISTRO
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/secretsmanager/SecretsManagerClient.h>
#include <aws/secretsmanager/model/GetSecretValueRequest.h>
#endif

#define LEASE_ID_LENGTH 10
#define UNIX_SOCKET_NAME "credentials_fetcher.sock"
#define INPUT_CREDENTIALS_LENGTH 104

// invalid character in username/account name
//https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb726984
//          (v=technet.10)
static const std::vector<char> invalid_characters = {
    '&', '|', ';', ':', '$', '*', '?', '<', '>', '!',' ', '\\', '.',']', '[', '+', '\'', '`', '~'};

static const std::vector<char> invalid_characters_ad_name = {
    '&', ':', ']', '[', '+', '|', ';', '$', '*', '?', '<', '>', '!',' ', '/', '\\', '\'', '`', '~'};


std::string dummy_credspec =
        "{\"CmsPlugins\":[\"ActiveDirectory\"],\"DomainJoinConfig\":{\"Sid\":\"S-1-5-21-4066351383-705263209-1606769140\",\"MachineAccountName\":\"webapp01\",\"Guid\":\"ac822f13-583e-49f7-aa7b-284f9a8c97b6\",\"DnsTreeName\":\"contoso.com\",\"DnsName\":\"contoso.com\",\"NetBiosName\":\"contoso\"},\"ActiveDirectoryConfig\":{\"GroupManagedServiceAccounts\":[{\"Name\":\"webapp01\",\"Scope\":\"contoso.com\"},{\"Name\":\"webapp01\",\"Scope\":\"contoso\"}],\"HostAccountConfig\":{\"PortableCcgVersion\":\"1\",\"PluginGUID\":\"{859E1386-BDB4-49E8-85C7-3070B13920E1}\",\"PluginInput\":{\"CredentialArn\":\"arn:aws:secretsmanager:us-west-2:123456789:secret:gMSAUserSecret-PwmPaO\"}}}}";


/**
 *
 * @param value - string input for the domain
 * @return true or false if string contains or not contains invalid characters
 */
bool isValidDomain(const std::string& value)
{

    // Regex to check valid domain name.
    std::regex pattern("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$");

    // If the domain name
    // is empty return false
    if (value.empty())
    {
        return false;
    }

    // Return true if the domain name
    // matched the ReGex
    if(std::regex_match(value, pattern))
    {
        return true;
    }
    return false;
}

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

/**
 *
 * @param value - string input that has to be validated
 * @return true or false if string contains or not contains invalid characters
 */
bool contains_invalid_characters_in_ad_account_name( const std::string& value )
{
    bool result = false;
    // Iterate over all characters in invalid_path_characters vector
    for ( const char& ch : invalid_characters_ad_name )
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


bool IsTestInvocationForUnitTests(std::string arn)
{
    std::string substr = "functionaltestcfspec";
    if (arn.find(substr) != std::string::npos) {
        return  true;
    }
    return  false;
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
    void RunServer( std::string& unix_socket_dir, std::string& krb_files_dir,
                     creds_fetcher::CF_logger& cf_logger, std::string& aws_sm_secret_name )
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
        std::cout << getCurrentTime() << '\t' << "INFO: Server listening on " << server_address
                  << std::endl;

        // Proceed to the server's main loop.
        HandleRpcs( krb_files_dir, cf_logger, aws_sm_secret_name );
    }

  private:
    // Class encompasing the state and logic needed to serve a request.
    class CallDataHealthCheck
    {
    public:
        std::string cookie;

#define CLASS_NAME_CallDataHealthCheck "CallDataHealthCheck"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataHealthCheck(
                credentialsfetcher::CredentialsFetcherService::AsyncService* service,
                grpc::ServerCompletionQueue* cq )
                : service_( service )
                , cq_( cq )
                , health_check_responder_( &health_check_ctx_ )
                , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataHealthCheck;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed(creds_fetcher::CF_logger& cf_logger)
        {
            if ( cookie.compare( CLASS_NAME_CallDataHealthCheck ) != 0 )
            {
                return;
            }

            std::cout << getCurrentTime() << '\t' << "INFO: CallDataHealthCheck " << this << " "
                                                                                          "status: "
                                                                                       "" <<
                status_ << std::endl;
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHealthCheck requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestHealthCheck( &health_check_ctx_, &health_check_request_,
                                                      &health_check_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataHealthCheck( service_, cq_ );

                // The actual processing.
                health_check_reply_.set_status( "OK" );
                status_ = FINISH;
                health_check_responder_.Finish( health_check_reply_, grpc::Status::OK, this );

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
            if ( cookie.compare( CLASS_NAME_CallDataHealthCheck ) != 0 )
            {
                return;
            }
            std::cout << getCurrentTime() << '\t' << "INFO: CallDataHealthCheck " << this << " "
                                                                                          "status: "
                                                                                       "" <<
                status_ << std::endl;
            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHealthCheck requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestHealthCheck( &health_check_ctx_, &health_check_request_,
                                                      &health_check_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataHealthCheck( service_, cq_ );

                // The actual processing.
                health_check_reply_.set_status( "OK" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                health_check_responder_.Finish( health_check_reply_, grpc::Status::OK, this );
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
        grpc::ServerContext health_check_ctx_;

        // What we get from the client.
        credentialsfetcher::HealthCheckRequest health_check_request_;
        // What we send back to the client.
        credentialsfetcher::HealthCheckResponse health_check_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher::HealthCheckResponse>
                health_check_responder_;

        // Let's implement a tiny state machine with the following states.
        enum CallStatus
        {
            CREATE,
            PROCESS,
            FINISH
        };
        CallStatus status_; // The current serving state.
    };

#if AMAZON_LINUX_DISTRO

    // Class encompasing the state and logic needed to serve a request.
    class CallDataCreateKerberosArnLease
    {
    public:
        std::string cookie;
#define CLASS_NAME_CallDataCreateKerberosArnLease "CallDataCreateKerberosArnLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataCreateKerberosArnLease(
                credentialsfetcher::CredentialsFetcherService::AsyncService* service,
                grpc::ServerCompletionQueue* cq )
                : service_( service )
                , cq_( cq )
                , create_arn_krb_responder_( &add_krb_ctx_ )
                , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataCreateKerberosArnLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataCreateKerberosArnLease ) != 0 )
            {
                return;
            }

            std::cout << getCurrentTime() << '\t' << "INFO: CallDataCreateKerberosArnLease " <<
                this << "status: " << status_ << std::endl;

            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestAddKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestAddKerberosArnLease( &add_krb_ctx_, &create_arn_krb_request_,
                                                   &create_arn_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS ) {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataCreateKerberosArnLease(service_, cq_);
                // The actual processing.
                std::string lease_id = "";
                std::list<creds_fetcher::krb_ticket_info *> krb_ticket_info_list;
                std::list<creds_fetcher::krb_ticket_arn_mapping *> krb_ticket_arn_mapping_list;
                std::unordered_set<std::string> krb_ticket_dirs;
                std::string accessId = create_arn_krb_request_.access_key_id();
                std::string secretKey = create_arn_krb_request_.secret_access_key();
                std::string sessionToken = create_arn_krb_request_.session_token();
                std::string region = create_arn_krb_request_.region();

                std::string username = "";
                std::string password = "";
                std::string domain = "";
                bool isTest = false;

                std::string err_msg;
                int credspecSize = create_arn_krb_request_.credspec_arns_size();

                if ( !accessId.empty() && !secretKey.empty() && !sessionToken.empty() && !region
                                                                                              .empty() && credspecSize > 0)
                {
                    for ( int i = 0; i < create_arn_krb_request_.credspec_arns_size(); i++ )
                    {
                        creds_fetcher::krb_ticket_info* krb_ticket_info =
                            new creds_fetcher::krb_ticket_info;
                        creds_fetcher::krb_ticket_arn_mapping* krb_ticket_arns =
                            new creds_fetcher::krb_ticket_arn_mapping;

                        std::string credspecarn = create_arn_krb_request_.credspec_arns( i );
                        if ( credspecarn.empty())
                        {
                            err_msg = "ERROR: credentialspec arn should not be empty/not properly"
                                      " formatted";

                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }


                        std::vector<std::string> results =
                            split_string( create_arn_krb_request_.credspec_arns( i ), '#' );

                        if(results.size() != 2)
                        {
                            err_msg = "ERROR: credentialspec arn is not valid";

                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }

                        std::vector<std::string> pathResults =
                            split_string( results[1], '/' );

                        if(pathResults.size() != 2 || contains_invalid_characters_in_credentials
                             (results[1]))
                        {
                            err_msg = "ERROR: mount path is invalid";

                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }

                        isTest = IsTestInvocationForUnitTests( results[0] );

                        if ( !isTest )
                        {

                            // get credentialspec contents:
                            Aws::Auth::AWSCredentials creds =
                                get_credentials( accessId, secretKey, sessionToken );
                            std::string response =
                                retrieve_credspec_from_s3( results[0], region, creds, false );

                            if ( response.empty() )
                            {
                                err_msg = "ERROR: credentialspec cannot be retrieved from s3";

                                std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                                break;
                            }
                            krb_ticket_arns->credential_spec_arn = results[0];
                            int parse_result = parse_cred_spec_domainless(
                                response, krb_ticket_info, krb_ticket_arns );

                            // only add the ticket info if the parsing is successful
                            if ( parse_result == 0 )
                            {
                                // retrieve domainless user credentials
                                std::tuple<std::string, std::string> userCreds =
                                    retrieve_credspec_from_secrets_manager(
                                        krb_ticket_arns->credential_domainless_user_arn, region,
                                        creds );

                                username = std::get<0>( userCreds );
                                password = std::get<1>( userCreds );
                                domain = krb_ticket_info->domain_name;

                                if ( isValidDomain( domain ) &&
                                     !contains_invalid_characters_in_ad_account_name( username ) )
                                {
                                    if ( !username.empty() && !password.empty() &&
                                         !domain.empty() &&
                                         username.length() < INPUT_CREDENTIALS_LENGTH &&
                                         password.length() < INPUT_CREDENTIALS_LENGTH )
                                    {

                                        std::string krb_files_path =
                                            krb_files_dir + "/" + results[1];
                                        std::vector<std::string> mountpath =
                                            split_string( results[1], '/' );

                                        // get taskid information
                                        lease_id = mountpath[0];

                                        krb_ticket_info->krb_file_path = krb_files_path;
                                        krb_ticket_info->domainless_user = username;
                                        krb_ticket_arns->krb_file_path = krb_files_path;

                                        // handle duplicate service accounts
                                        if ( !krb_ticket_dirs.count( krb_files_path ) )
                                        {
                                            krb_ticket_dirs.insert( krb_files_path );
                                            krb_ticket_info_list.push_back( krb_ticket_info );
                                            krb_ticket_arn_mapping_list.push_back(
                                                krb_ticket_arns );
                                        }
                                        else
                                        {
                                            err_msg = "ERROR: found duplicate mount paths";
                                            std::cout << getCurrentTime() << '\t' << err_msg
                                                      << std::endl;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        err_msg =
                                            "ERROR: domainless AD user credentials is not valid/ "
                                            "credentials should not be more than 256 charaters";
                                        std::cout << getCurrentTime() << '\t' << err_msg
                                                  << std::endl;
                                        break;
                                    }
                                }
                                else
                                {
                                    err_msg = "ERROR: invalid domainName/username";
                                    std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                                    break;
                                }
                            }
                        }
                        else{
                            std::string krb_files_path =
                                krb_files_dir + "/" + results[1];
                            std::vector<std::string> mountpath =
                                split_string( results[1], '/' );

                            // get taskid information
                            lease_id = mountpath[0];
                            std::filesystem::create_directories( krb_files_path );
                            std::string dummyFile = krb_files_path+"/krb5cc";
                            std::ofstream o(dummyFile);
                        }
                    }
                }
                else
                {
                        err_msg = "Error: access credentials should not be empty";
                        std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                }

                create_arn_krb_reply_.set_lease_id(lease_id);

                if ( err_msg.empty() && !isTest)
                {
                    // create the kerberos tickets for the service accounts
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        // invoke to get machine ticket
                        int status = 0;
                        if ( username.empty()  ||  password.empty() )
                        {
                            cf_logger.logger( LOG_ERR, "Invalid credentials for "
                                                       "domainless user ", username.c_str());
                            err_msg = "ERROR: Invalid credentials for domainless user";
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }
                        status = get_domainless_user_krb_ticket( domain,
                                                                 username, password,
                                                                 cf_logger );
                        if ( status < 0 )
                        {
                            cf_logger.logger( LOG_ERR, "Error %d: cannot domainless user kerberos tickets",
                                              status );
                            err_msg = "ERROR: cannot retrieve domainless user kerberos tickets";
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }

                        std::string krb_file_path = krb_ticket->krb_file_path;
                        std::filesystem::create_directories( krb_file_path );

                        std::string krb_ccname_str = krb_ticket->krb_file_path + "/krb5cc";

                        if ( !std::filesystem::exists( krb_ccname_str ) )
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
                            std::cout << getCurrentTime() << '\t' << err_msg <<
                                std::endl;
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                              status );
                            break;
                        }
                        else
                        {
                            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                              gmsa_ticket_result.second.c_str() );
                            std::cout << getCurrentTime() << '\t' << "INFO: gMSA ticket is "
                                                                        "created"
                                      << std::endl;
                        }
                    }
                }
                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() && !isTest)
                {
                    username = "xxxx";
                    password = "xxxx";
                    accessId = "xxxx";
                    sessionToken = "xxxx";
                    secretKey = "xxxx";
                    // remove the directories on failure
                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        std::filesystem::remove_all( krb_ticket->krb_file_path );
                    }
                    status_ = FINISH;
                    create_arn_krb_responder_.Finish(
                          create_arn_krb_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                            this );
                }
                else
                {
                    if(!isTest)
                    {
                        for ( auto arn_mapping : krb_ticket_arn_mapping_list )
                        {
                            credentialsfetcher::KerberosTicketArnResponse krb_ticket_response;
                            krb_ticket_response.set_credspec_arns(
                                arn_mapping->credential_spec_arn );
                            krb_ticket_response.set_created_kerberos_file_paths(
                                arn_mapping->krb_file_path );
                            create_arn_krb_reply_.add_krb_ticket_response_map()->CopyFrom(
                                krb_ticket_response );
                        }

                        username = "xxxx";
                        password = "xxxx";
                        accessId = "xxxx";
                        sessionToken = "xxxx";
                        secretKey = "xxxx";
                        // write the ticket information to meta data file
                        write_meta_data_json( krb_ticket_info_list, lease_id, krb_files_dir );
                    }
                    status_ = FINISH;
                    create_arn_krb_responder_.Finish( create_arn_krb_reply_, grpc::Status::OK,
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
            if ( cookie.compare( CLASS_NAME_CallDataCreateKerberosArnLease ) != 0 )
            {
                return;
            }

            std::cout << getCurrentTime() << '\t' << "INFO: CallDataCreateKerberosArnLease " <<
                this << "status: " << status_ << std::endl;

            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestAddKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestAddKerberosArnLease( &add_krb_ctx_, &create_arn_krb_request_,
                                                   &create_arn_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataCreateKerberosArnLease( service_, cq_ );
                // The actual processing.
                create_arn_krb_reply_.set_lease_id( "12345" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                create_arn_krb_responder_.Finish( create_arn_krb_reply_, grpc::Status::OK, this );
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
        credentialsfetcher::KerberosArnLeaseRequest create_arn_krb_request_;
        // What we send back to the client.
        credentialsfetcher::CreateKerberosArnLeaseResponse create_arn_krb_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher::CreateKerberosArnLeaseResponse>
                create_arn_krb_responder_;

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
    class CallDataRenewKerberosArnLease
    {
      public:
        std::string cookie;
#define CLASS_NAME_CallDataRenewKerberosArnLease \
    "CallDataRenewKerberosArnLease"
        // Take in the "service" instance (in this case representing an asynchronous
        // server) and the completion queue "cq" used for asynchronous communication
        // with the gRPC runtime.
        CallDataRenewKerberosArnLease(
            credentialsfetcher::CredentialsFetcherService::AsyncService* service,
            grpc::ServerCompletionQueue* cq )
            : service_( service )
            , cq_( cq )
            , handle_krb_responder_( &add_krb_ctx_ )
            , status_( CREATE )
        {
            cookie = CLASS_NAME_CallDataRenewKerberosArnLease;
            // Invoke the serving logic right away.
            Proceed();
        }

        void Proceed( std::string krb_files_dir, creds_fetcher::CF_logger& cf_logger,
                      std::string aws_sm_secret_name )
        {
            if ( cookie.compare( CLASS_NAME_CallDataRenewKerberosArnLease ) != 0 )
            {
                return;
            }

            std::cout << getCurrentTime() << '\t' << "INFO: RenewKerberosArnLease " <<
                this << "status: " << status_ << std::endl;

            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestRenewKerberosArnLease( &add_krb_ctx_,
                                                        &renew_krb_arn_request_,
                                                        &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataRenewKerberosArnLease( service_, cq_ );
                // The actual processing.
                std::string accessId = renew_krb_arn_request_.access_key_id();
                std::string secretKey = renew_krb_arn_request_.secret_access_key();
                std::string sessionToken = renew_krb_arn_request_.session_token();
                std::string region = renew_krb_arn_request_.region();
                std::string username = "";
                std::string password = "";
                std::string domain = "";

                std::string err_msg;
                if ( !accessId.empty() && !secretKey.empty() && !sessionToken.empty() && !region.empty() )
                {
                        std::vector<std::string> metadatafiles =
                            get_meta_data_file_paths( krb_files_dir );
                        for ( auto file_path : metadatafiles )
                        {
                            creds_fetcher::krb_ticket_info* krb_ticket_info =
                                new creds_fetcher::krb_ticket_info;
                            creds_fetcher::krb_ticket_arn_mapping* krb_ticket_arns =
                                new creds_fetcher::krb_ticket_arn_mapping;
                            std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list =
                                read_meta_data_json( file_path );
                            // refresh the kerberos tickets for the service accounts, if tickets ready for renewal
                            for ( auto krb_ticket : krb_ticket_info_list )
                            {
                                std::string credspec_info = krb_ticket->credspec_info;
                                if ( !credspec_info.empty() )
                                {
                                    // get credentialspec contents:
                                    Aws::Auth::AWSCredentials creds =
                                        get_credentials( accessId, secretKey, sessionToken );
                                    std::string response = retrieve_credspec_from_s3(
                                        credspec_info, region, creds, false );

                                    if ( response.empty() )
                                    {
                                        err_msg =
                                            "ERROR: credentialspec cannot be retrieved from s3";
                                        std::cout << getCurrentTime() << '\t' << err_msg
                                                  << std::endl;
                                        break;
                                    }

                                    int parse_result = parse_cred_spec_domainless(
                                        response, krb_ticket_info, krb_ticket_arns );

                                    // only add the ticket info if the parsing is successful
                                    if ( parse_result == 0 )
                                    {
                                        // retrieve domainless user credentials
                                        std::tuple<std::string, std::string> userCreds =
                                            retrieve_credspec_from_secrets_manager(
                                                krb_ticket_arns->credential_domainless_user_arn,
                                                region, creds );

                                        username = std::get<0>( userCreds );
                                        password = std::get<1>( userCreds );
                                        domain = krb_ticket_info->domain_name;

                                        if ( isValidDomain(domain) &&
                                             !contains_invalid_characters_in_ad_account_name( username ) )
                                        {
                                            if ( !username.empty() && !password.empty() &&
                                                 !domain.empty() &&
                                                 username.length() < INPUT_CREDENTIALS_LENGTH &&
                                                 password.length() < INPUT_CREDENTIALS_LENGTH )
                                            {
                                                std::string renewal_path =
                                                    renew_gmsa_ticket( krb_ticket, domain, username,
                                                                       password, cf_logger );
                                            }
                                            else
                                            {
                                                err_msg = "ERROR: domainless AD user credentials is not valid/ "
                                                          "credentials should not be more than 256 charaters";
                                                std::cout << getCurrentTime() << '\t' << err_msg
                                                          << std::endl;
                                            }
                                        }
                                        else
                                        {
                                            err_msg = "ERROR: invalid domainName/username";
                                            std::cout << getCurrentTime() << '\t' << err_msg
                                                      << std::endl;
                                        }
                                    }
                                }
                            }
                        }
                    }


                username = "xxxx";
                password = "xxxx";
                accessId = "xxxx";
                secretKey = "xxxx";
                sessionToken = "xxxx";

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                if ( !err_msg.empty() )
                {
                    renew_krb_arn_reply_.set_status("failed");
                    status_ = FINISH;
                    handle_krb_responder_.Finish(
                        renew_krb_arn_reply_, grpc::Status( grpc::StatusCode::INTERNAL, err_msg ),
                        this );
                }
                else
                {
                    renew_krb_arn_reply_.set_status("successful");
                    status_ = FINISH;
                    handle_krb_responder_.Finish( renew_krb_arn_reply_, grpc::Status::OK, this );
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
            if ( cookie.compare( CLASS_NAME_CallDataRenewKerberosArnLease ) != 0 )
            {
                return;
            }
            std::cout << getCurrentTime() << '\t' << "INFO: RenewKerberosArnLease " <<
                this << "status: " << status_ << std::endl;

            if ( status_ == CREATE )
            {
                // Make this instance progress to the PROCESS state.
                status_ = PROCESS;

                // As part of the initial CREATE state, we *request* that the system
                // start processing RequestHandleNonDomainJoinedKerberosLease requests. In this request, "this" acts
                // are the tag uniquely identifying the request (so that different CallData
                // instances can serve different requests concurrently), in this case
                // the memory address of this CallData instance.

                service_->RequestRenewKerberosArnLease( &add_krb_ctx_,
                                                        &renew_krb_arn_request_,
                                                        &handle_krb_responder_, cq_, cq_, this );
            }
            else if ( status_ == PROCESS )
            {
                // Spawn a new CallData instance to serve new clients while we process
                // the one for this CallData. The instance will deallocate itself as
                // part of its FINISH state.
                new CallDataRenewKerberosArnLease(service_, cq_ );
                // The actual processing.
                renew_krb_arn_reply_.set_status(
                    "Successful" );

                // And we are done! Let the gRPC runtime know we've finished, using the
                // memory address of this instance as the uniquely identifying tag for
                // the event.
                status_ = FINISH;
                handle_krb_responder_.Finish( renew_krb_arn_reply_, grpc::Status::OK,
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
        credentialsfetcher::RenewKerberosArnLeaseRequest
            renew_krb_arn_request_;
        // What we send back to the client.
        credentialsfetcher::RenewKerberosArnLeaseResponse renew_krb_arn_reply_;

        // The means to get back to the client.
        grpc::ServerAsyncResponseWriter<credentialsfetcher
                                        ::RenewKerberosArnLeaseResponse>
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

#endif

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

            std::cout << getCurrentTime() << '\t' << "INFO: CallDataCreateKerberosLease " <<
                this << "status: " << status_ << std::endl;

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
                                                        krb_ticket_info );

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
                        std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
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
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }

                        std::string krb_file_path = krb_ticket->krb_file_path;
                        if ( std::filesystem::exists( krb_file_path ) )
                        {
                            cf_logger.logger( LOG_INFO,
                                              "Directory already exists: "
                                              "%s",
+                                              krb_file_path.c_str() );
                            break;
                        }
                        std::filesystem::create_directories( krb_file_path );

                        std::string krb_ccname_str = krb_ticket->krb_file_path + "/krb5cc";

                        if ( !std::filesystem::exists( krb_ccname_str ) )
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
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                              status );
                            break;
                        }
                        else
                        {
                            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                              gmsa_ticket_result.second.c_str() );
                            std::cout << getCurrentTime() << '\t' << "INFO: gMSA ticket is at "
                                                                        "" <<
                                gmsa_ticket_result.second
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
                        std::filesystem::remove_all( krb_ticket->krb_file_path );
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
            std::cout << getCurrentTime() << '\t' << "INFO: CallDataCreateKerberosLease " <<
                this << "status: " << status_ << std::endl;

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

            std::cout << getCurrentTime() << '\t' << "INFO: AddNonDomainJoinedKerberosLease " <<
                this << "status: " << status_ << std::endl;

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
                if(isValidDomain(domain) &&
                     !contains_invalid_characters_in_ad_account_name(username))
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
                                krb_ticket_info );

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
                                std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                                break;
                            }
                        }
                    }
                    else
                    {
                        err_msg = "Error: domainless AD user credentials is not valid/ "
                                  "credentials should not be more than 256 charaters";
                        std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                    }
                }
                else
                {
                   err_msg = "Error: invalid domainName/username";
                   std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
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
                                                       "domainless user ", username.c_str());
                            err_msg = "ERROR: Invalid credentials for domainless user";
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }
                        status = get_domainless_user_krb_ticket( domain,
                                                                 username, password,
                                                                     cf_logger );
                        if ( status < 0 )
                        {
                            cf_logger.logger( LOG_ERR, "Error %d: cannot domainless user kerberos tickets",
                                              status );
                            err_msg = "ERROR: cannot retrieve domainless user kerberos tickets";
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            break;
                        }

                        std::string krb_file_path = krb_ticket->krb_file_path;
                        if ( std::filesystem::exists( krb_file_path ) )
                        {
                            cf_logger.logger( LOG_INFO,
                                              "Directory already exists: "
                                              "%s",
                                              krb_file_path.c_str() );
                            break;
                        }
                        std::filesystem::create_directories( krb_file_path );

                        std::string krb_ccname_str = krb_ticket->krb_file_path + "/krb5cc";

                        if ( !std::filesystem::exists( krb_ccname_str ) )
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
                            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                              status );
                            break;
                        }
                        else
                        {
                            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                              gmsa_ticket_result.second.c_str() );
                            std::cout << getCurrentTime() << '\t' << "INFO: gMSA ticket is "
                                                                        "created"
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
                        std::filesystem::remove_all( krb_ticket->krb_file_path );
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
            std::cout << getCurrentTime() << '\t' << "INFO: AddNonDomainJoinedKerberosLease " <<
                this << "status: " << status_ << std::endl;

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

            std::cout << getCurrentTime() << '\t' << "INFO: RenewNonDomainJoinedKerberosLease " <<
                this << "status: " << status_ << std::endl;

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
                std::string username = renew_domainless_krb_request_.username();
                std::string password = renew_domainless_krb_request_.password();
                std::string domain = renew_domainless_krb_request_.domain();

                std::string err_msg;
                if(isValidDomain(domain) &&
                     !contains_invalid_characters_in_ad_account_name(username))
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
                        std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
                    }
                }
                else
                {
                    err_msg = "Error: invalid domainName/username";
                    std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
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
            std::cout << getCurrentTime() << '\t' << "INFO: RenewNonDomainJoinedKerberosLease " <<
                this << "status: " << status_ << std::endl;
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
            std::cout << getCurrentTime() << '\t' << "INFO: CallDataDeleteKerberosLease " <<
                this << "status: " << status_ << std::endl;

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
                    std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
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
            std::cout << getCurrentTime() << '\t' << "INFO: CallDataDeleteKerberosLease " <<
                this << "status: " << status_ << std::endl;

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
        new CallDataHealthCheck( &service_, cq_.get() );

#if AMAZON_LINUX_DISTRO
        new CallDataCreateKerberosArnLease( &service_, cq_.get() );
        new CallDataRenewKerberosArnLease( &service_, cq_.get() );
#endif

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
            static_cast<CallDataHealthCheck*>( got_tag )->Proceed( cf_logger);

#if AMAZON_LINUX_DISTRO
            static_cast<CallDataCreateKerberosArnLease*>( got_tag )->Proceed( krb_files_dir, cf_logger,
                                                                           aws_sm_secret_name );
            static_cast<CallDataRenewKerberosArnLease*>( got_tag )->Proceed( krb_files_dir, cf_logger,
                                                                         aws_sm_secret_name );
#endif
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
 * Check health of credentials-fetcher daemon
 * @return - int
 */
int HealthCheck(std::string serviceName)
{
    try
    {
     std::string server_address{ "unix:/var/credentials-fetcher/socket/credentials_fetcher.sock" };
    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel( server_address,
                                                                grpc::InsecureChannelCredentials());
    std::unique_ptr<credentialsfetcher::CredentialsFetcherService::Stub> stub =  credentialsfetcher::CredentialsFetcherService::NewStub( channel );
    // Prepare request
    credentialsfetcher::HealthCheckRequest request;
    request.set_service( serviceName );

    credentialsfetcher::HealthCheckResponse response;
    grpc::ClientContext context;
    grpc::Status status;
        // Send request
        status = stub->HealthCheck( &context, request, &response );

        // Handle response
        if ( status.ok() )
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
    catch ( ... )
    {
        return 1;
    }

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
int parse_cred_spec( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info )
{
    try
    {
        if ( credspec_data.empty() )
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: credspec is empty"<< std::endl;
            return -1;
        }

        Json::Value root;
        Json::CharReaderBuilder reader;
        std::istringstream credspec_stream(credspec_data);
        std::string errors;
        Json::parseFromStream(reader, credspec_stream, &root, &errors);
        // get domain name from credspec
        std::string domain_name = root["DomainJoinConfig"]["DnsName"].asString();
        // get service account name from credspec
        std::string service_account_name;
        const Json::Value& gmsa_array = root["ActiveDirectoryConfig"]["GroupManagedServiceAccounts"];
        for (const Json::Value& gmsa : gmsa_array)
        {
            service_account_name = gmsa["Name"].asString();
            if (!service_account_name.empty())
                break;
        }
        if (service_account_name.empty() || domain_name.empty())
            return -1;

        if(!isValidDomain(domain_name) ||
             contains_invalid_characters_in_ad_account_name(service_account_name))
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: credentialspec file is not formatted"
                                                     " properly" <<
                std::endl;
            return -1;
        }

        krb_ticket_info->domain_name = domain_name;
        krb_ticket_info->service_account_name = service_account_name;
    }
    catch ( ... )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: domain-joined credspec is not properly "
                                                 "formatted "
                                                 "failed" << std::endl;
        return -1;
    }

    return 0;
}

/**
 * This function parses the cred spec file.
 * The cred spec file is in json format.
 * @param credspec - service account information
 * @param krb_ticket_info - return service account info
 * @param krb_ticket_mapping - return service account info
 * @return
 */
int parse_cred_spec_domainless( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info, creds_fetcher::krb_ticket_arn_mapping* krb_ticket_mapping )
{
    try
    {
        if ( credspec_data.empty() )
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: credspec is empty"<< std::endl;
            return -1;
        }

        Json::Value root;
        Json::CharReaderBuilder reader;
        std::istringstream credspec_stream(credspec_data);
        std::string errors;
        Json::parseFromStream(reader, credspec_stream, &root, &errors);
        // get domain name from credspec
        std::string domain_name = root["DomainJoinConfig"]["DnsName"].asString();
        // get service account name from credspec
        std::string service_account_name;
        const Json::Value& gmsa_array = root["ActiveDirectoryConfig"]["GroupManagedServiceAccounts"];
        for (const Json::Value& gmsa : gmsa_array)
        {
            service_account_name = gmsa["Name"].asString();
            if (!service_account_name.empty())
                break;
        }
        if (service_account_name.empty() || domain_name.empty())
            return -1;

        if(!isValidDomain(domain_name) ||
             contains_invalid_characters_in_ad_account_name(service_account_name))
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: credentialspec file is not formatted"
                                                     " properly" <<
                std::endl;
            return -1;
        }

        // get credentialspec arn
        std::string domainless_user_arn = root["ActiveDirectoryConfig"]["HostAccountConfig"]["PluginInput"]["CredentialArn"].asString();
        if (domainless_user_arn.empty())
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: secrets manager arn is not valid" <<
                std::endl;
            return -1;
        }

        krb_ticket_info->domain_name = domain_name;
        krb_ticket_info->service_account_name = service_account_name;
        krb_ticket_info->credspec_info = krb_ticket_mapping->credential_spec_arn;

        krb_ticket_mapping->credential_domainless_user_arn = domainless_user_arn;
        krb_ticket_mapping->krb_file_path =  krb_ticket_info->krb_file_path;
    }
    catch ( ... )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: domainless credspec is not properly "
                                                 "formatted "
                                                 "failed" << std::endl;
        return -1;
    }

    return 0;
}

/**
 * ProcessCredSpecFile - Processes a provided credential spec file
 * @param krb_files_dir - Kerberos TGT directory
 * @param credspec_filepath - Path to credential spec file produced by DC
 * @param cf_logger - log to systemd daemon
 * @param cred_file_lease_id - The lease id to use for this credential spec file
 * @return - return 0 on success
 */
int ProcessCredSpecFile(std::string krb_files_dir, std::string credspec_filepath, creds_fetcher::CF_logger& cf_logger, std::string cred_file_lease_id) {
    std::string err_msg;
    std::string credspec_contents;
    
    cf_logger.logger( LOG_INFO, "Generating lease id %s", cred_file_lease_id.c_str());

    if ( !std::filesystem::exists( credspec_filepath ) ){
        std::cout << getCurrentTime() << '\t' << "The credential spec file " << credspec_filepath << " was not found!" << std::endl;
        cf_logger.logger( LOG_ERR, "The credential spec file %s was not found!",
                                    credspec_filepath.c_str() );
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(credspec_filepath);
    if (inputFile.is_open()) 
    {
        credspec_contents.assign((std::istreambuf_iterator<char>(inputFile)),
                                std::istreambuf_iterator<char>());
        
        inputFile.close(); // Close the file
    } 
    else 
    {
        cf_logger.logger( LOG_ERR, "Unable to open credential spec file: %s", credspec_filepath.c_str());
        std::cout << getCurrentTime() << '\t' << "Unable to open credential spec file: " <<
            credspec_filepath <<
            std::endl;

        return EXIT_FAILURE;
    }

    creds_fetcher::krb_ticket_info* krb_ticket_info = new creds_fetcher::krb_ticket_info;
    int parse_result = parse_cred_spec( credspec_contents, krb_ticket_info );

    // only add the ticket info if the parsing is successful
    if ( parse_result == EXIT_SUCCESS )
    {
        std::string krb_files_path = krb_files_dir + "/" + cred_file_lease_id + "/" +
                                        krb_ticket_info->service_account_name;
        krb_ticket_info->krb_file_path = krb_files_path;
        krb_ticket_info->domainless_user = "";
        krb_ticket_info->credspec_info = "";
    }
    else
    {
        err_msg = "Error: credential spec provided is not properly formatted";
        std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
    }
    
    if ( err_msg.empty() )
    {
        int status;
        // invoke to get machine ticket
        status = get_machine_krb_ticket( krb_ticket_info->domain_name, cf_logger );
        if ( status < 0 )
        {
            cf_logger.logger( LOG_ERR, "Error %d: Cannot get machine krb ticket",
                                status );
            delete krb_ticket_info;      
                  
            return EXIT_FAILURE;
        }

        std::string krb_file_path = krb_ticket_info->krb_file_path;
        if ( std::filesystem::exists( krb_file_path ) )
        {
            cf_logger.logger( LOG_INFO,
                                "Deleting existing credential file directory %s",
+                                              krb_file_path.c_str() );

            std::filesystem::remove_all(krb_file_path);
        }
        std::filesystem::create_directories( krb_file_path );

        std::string krb_ccname_str = krb_ticket_info->krb_file_path + "/krb5cc";

        if ( !std::filesystem::exists( krb_ccname_str ) )
        {
            std::ofstream file( krb_ccname_str );
            file.close();

            krb_ticket_info->krb_file_path = krb_ccname_str;
        }

        std::pair<int, std::string> gmsa_ticket_result = get_gmsa_krb_ticket(
            krb_ticket_info->domain_name, krb_ticket_info->service_account_name,
            krb_ccname_str, cf_logger );
        if ( gmsa_ticket_result.first != 0 )
        {
            err_msg = "ERROR: Cannot get gMSA krb ticket";
            std::cout << getCurrentTime() << '\t' << err_msg << std::endl;
            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                status );
        }
        else
        {
            chmod(krb_ccname_str.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                gmsa_ticket_result.second.c_str() );
            std::cout << getCurrentTime() << '\t' << "INFO: gMSA ticket is created"
                        << std::endl;
        }
    }

    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    if ( !err_msg.empty() )
    {
        // remove the directory on failure
        std::filesystem::remove_all( krb_ticket_info->krb_file_path );

        std::cerr << err_msg << std::endl;
        cf_logger.logger( LOG_ERR, "%s", err_msg.c_str() );
        delete krb_ticket_info;

        return EXIT_FAILURE;
    }
    
    // write the ticket information to meta data file
    write_meta_data_json( krb_ticket_info, cred_file_lease_id, krb_files_dir );

    delete krb_ticket_info;

    return EXIT_SUCCESS;
}


#if AMAZON_LINUX_DISTRO
// initialize credentials
Aws::Auth::AWSCredentials get_credentials(std::string accessKeyId, std::string secretKey, std::string sessionToken)
{
    Aws::Auth::AWSCredentials credentials;
    credentials.SetAWSAccessKeyId(Aws::String(accessKeyId));
    credentials.SetAWSSecretKey(Aws::String(secretKey));
    credentials.SetSessionToken(Aws::String(sessionToken));
    return credentials;
}

// retrieve credspec from s3
// example : arn:aws:s3:::gmsacredspec/gmsa-cred-spec.json
std::string retrieve_credspec_from_s3(std::string s3_arn, std::string region, Aws::Auth::AWSCredentials credentials, bool test = false)
{
    std::string response = "";
    Aws::SDKOptions options;
    try {
        Aws::InitAPI(options);
        {
            Aws::Client::ClientConfiguration clientConfig;
            clientConfig.region = region;
            auto provider = Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("alloc-tag", credentials);
            auto creds = provider->GetAWSCredentials();
            if (creds.IsEmpty()) {
                std::cout << getCurrentTime() << '\t' << "ERROR: Failed authentication invalid creds" << std::endl;
                Aws::ShutdownAPI(options);
                return std::string("");
            }
            std::smatch arn_match;
            std::regex pattern("arn:([^:]+):s3:::([^/]+)/(.+)");
            if (!std::regex_search(s3_arn, arn_match, pattern)) {
                std::cout << getCurrentTime() << '\t' << "ERROR: s3 arn provided is not valid " <<
                    s3_arn << std::endl;
                Aws::ShutdownAPI(options);
                return std::string("");
            }
            std::string s3Bucket = std::string(arn_match[2]);
            std::string objectName = std::string(arn_match[3]);

            if(test)
            {
                std::cout << s3Bucket;
                std::cout << objectName;
                return dummy_credspec;
            }

            Aws::S3::S3Client s3Client (credentials,Aws::MakeShared<Aws::S3::S3EndpointProvider>
                (Aws::S3::S3Client::ALLOCATION_TAG), clientConfig);
            Aws::S3::Model::GetObjectRequest request;
            request.SetBucket(s3Bucket);
            request.SetKey(objectName);
            Aws::S3::Model::GetObjectOutcome outcome =
                    s3Client.GetObject(request);

            if (!outcome.IsSuccess()) {
                const Aws::S3::S3Error &err = outcome.GetError();
                std::cout << getCurrentTime() << '\t' << "ERROR: GetObject: " <<
                          err.GetExceptionName() << ": " << err.GetMessage() << std::endl;
                return std::string("");
            }
            std::stringstream ss;
            ss << outcome.GetResult().GetBody().rdbuf();
            response = ss.str();
        }
    }
    catch ( ... )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: retrieving credentialspec from s3 "
                                                 "failed" << std::endl;
        return std::string("");
    }
    std::cout << getCurrentTime() << '\t' << "INFO: credentialspec info is successfully retrieved" << std::endl;
    return response;
}


// retrieve secrets from secrets manager
// example : arn:aws:secretsmanager:us-west-2:618112483929:secret:gMSAUserSecret-PwmPaO
std::tuple<std::string, std::string> retrieve_credspec_from_secrets_manager(std::string sm_arn, std::string region, Aws::Auth::AWSCredentials credentials)
{
    std::string response = "";
    Aws::SDKOptions options;
    try {
        Aws::InitAPI(options);
        {
            Aws::Client::ClientConfiguration clientConfig;
            clientConfig.region = region;
            auto provider = Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("alloc-tag", credentials);
            auto creds = provider->GetAWSCredentials();
            if (creds.IsEmpty()) {
                std::cout << getCurrentTime() << '\t' << "ERROR: failed authentication invalid "
                                                         "creds"
                                                          <<
                                                 std::endl;
                Aws::ShutdownAPI(options);
                return {"",""};
            }
            Aws::SecretsManager::SecretsManagerClient sm_client(credentials,
                                                                 Aws::MakeShared<Aws::SecretsManager::SecretsManagerEndpointProvider>( Aws::SecretsManager::SecretsManagerClient::ALLOCATION_TAG),clientConfig);
            Aws::SecretsManager::Model::GetSecretValueRequest requestsec;
            requestsec.SetSecretId(sm_arn);

            auto getSecretValueOutcome = sm_client.GetSecretValue(requestsec);
            if (getSecretValueOutcome.IsSuccess()) {
                response = getSecretValueOutcome.GetResult().GetSecretString();
            } else {
                std::cout << getCurrentTime() << '\t' << "ERROR: " << getSecretValueOutcome
                                                                       .GetError() << std::endl;
                return {"",""};
            }
        }

        Json::Value root;
        Json::CharReaderBuilder reader;
        std::istringstream sm_stream(response);
        std::string errors;
        Json::parseFromStream(reader, sm_stream, &root, &errors);
        std::cout << getCurrentTime() << '\t' << "INFO: gMSA user information is successfully "
                                                "retrieved" << std::endl;
        return {root["username"].asString(),root["password"].asString()};
    }
    catch ( ... )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: retrieving user info from secrets manager "
                                                 "failed"
                  <<
            std::endl;
        return {"",""};
    }
    return {"",""};
}
#endif
