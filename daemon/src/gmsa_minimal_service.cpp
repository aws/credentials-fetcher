//Extraction of methods that are needed for command line moe (No gRPC) that are intertwined with gRpc
#include "daemon.h"

#include <fstream>
#include <random>
#include <sys/stat.h>
#include <unordered_set>

#define LEASE_ID_LENGTH 10
#define UNIX_SOCKET_NAME "credentials_fetcher.sock"
#define INPUT_CREDENTIALS_LENGTH 256

static const std::vector<char> invalid_characters = {
    '&', '|', ';', '$', '*', '?', '<', '>', '!',' '};

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
            fprintf( stderr, SD_CRIT "credspec is empty" );
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


/**
 * ProcessCredSpecFile - Processes a provided credential spec file
 * @param krb_files_dir - Kerberos TGT directory
 * @param credspec_filepath - Path to credential spec file produced by DC
 * @param cf_logger - log to systemd daemon
 * @param cred_file_lease_id - The lease id to use for this credential spec file
 * @return - return 0 on success
 */
int ProcessCredSpecFile(std::string krb_files_dir, std::string credspec_filepath, creds_fetcher::CF_logger& cf_logger,
 std::string cred_file_lease_id,
 std::string aws_sm_secret_name) {
    std::unordered_set<std::string> krb_ticket_dirs;
    std::string err_msg;
    std::string credspec_contents;
    int status;
    
    cf_logger.logger( LOG_INFO, "Generating lease id %s", cred_file_lease_id );

    if ( !std::filesystem::exists( credspec_filepath ) ){
        std::cerr << "The credential spec file " << credspec_filepath << " was not found!" << std::endl;
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
        cf_logger.logger( LOG_ERR, "Unable to open credential spec file: %s", credspec_filepath);
        std::cerr << "Unable to open credential spec file: " << credspec_filepath << std::endl;

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
    }
    else
    {
        err_msg = "Error: credential spec provided is not properly formatted";
    }
    
    if ( err_msg.empty() )
    {
        if ( aws_sm_secret_name.length() != 0 )
        {
            status = get_user_krb_ticket( krb_ticket_info->domain_name,
                                          aws_sm_secret_name, cf_logger );
            krb_ticket_info->domainless_user =
                "awsdomainlessusersecret:"+aws_sm_secret_name;
	
            if ( status < 0 )
            {
                cf_logger.logger( LOG_ERR, "Error %d: Cannot get usr krb ticket",
                                    status );
                delete krb_ticket_info;
               return EXIT_FAILURE;
            }
	}
        else
        {
            // invoke to get machine ticket
            status = get_machine_krb_ticket( krb_ticket_info->domain_name, cf_logger );
            if ( status < 0 )
	    {
	        cf_logger.logger( LOG_ERR, "Error %d: Cannot get machine krb ticket",
	                            status );
	        delete krb_ticket_info;
               return EXIT_FAILURE;
            }
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
            std::cout << err_msg << std::endl;
            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket",
                                status );
        }
        else
        {
            chmod(krb_ccname_str.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

            cf_logger.logger( LOG_INFO, "gMSA ticket is at %s",
                                gmsa_ticket_result.second.c_str() );
            std::cout << "gMSA ticket is at " << gmsa_ticket_result.second
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
