#include "daemon.h"
#include <boost/filesystem.hpp>
#include <chrono>
#include <stdlib.h>

int krb_ticket_renew_handler( creds_fetcher::Daemon cf_daemon )
{
    std::string krb_files_dir = cf_daemon.krb_files_dir;
    int interval = cf_daemon.krb_ticket_handle_interval;
    creds_fetcher::CF_logger cf_logger = cf_daemon.cf_logger;

    if ( krb_files_dir.empty() )
    {
        fprintf( stderr, SD_CRIT "directory path for kerberos tickets is not provided" );
        return -1;
    }

    while ( !cf_daemon.got_systemd_shutdown_signal )
    {
        try
        {
            auto x = std::chrono::steady_clock::now() + std::chrono::minutes( interval );
            std::this_thread::sleep_until( x );
            std::cout << "###### renewal started ######" << std::endl;

            std::list<creds_fetcher::kube_config_info*> kube_config_info_list = parse_kube_config
                (cf_daemon.kube_config_file_path, cf_daemon.krb_files_dir);
            // identify the metadata files in the krb directory
            std::vector<std::string> metadatafiles;
            for ( boost::filesystem::recursive_directory_iterator end, dir( krb_files_dir );
                  dir != end; ++dir )
            {
                auto path = dir->path();
                if ( boost::filesystem::is_regular_file( path ) )
                {
                    // find the file with metadata extension
                    std::string filename = path.filename().string();
                    if ( !filename.empty() && filename.find( "_metadata" ) != std::string::npos )
                    {
                        std::string filepath = path.parent_path().string() + "/" + filename;
                        metadatafiles.push_back( filepath );
                    }
                }
            }

            // read the information of service account from the files
            for ( auto file_path : metadatafiles )
            {
                std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list =
                    read_meta_data_json( file_path );

                // refresh the kerberos tickets for the service accounts, if tickets ready for
                // renewal
                for ( auto krb_ticket : krb_ticket_info_list )
                {
                    std::pair<int, std::string> gmsa_ticket_result;
                    std::string krb_cc_name = krb_ticket->krb_file_path;
                    std::string domainless_user = krb_ticket->domainless_user;
                    // check if the ticket is ready for renewal and not created in domainless mode
                    if ( is_ticket_ready_for_renewal( krb_cc_name ) && domainless_user == "")
                    {
                        int num_retries = 1;
                        for ( int i = 0; i <= num_retries; i++ )
                        {
                            gmsa_ticket_result = get_gmsa_krb_ticket(
                                krb_ticket->domain_name, krb_ticket->service_account_name,
                                krb_cc_name, cf_logger );
                            if ( gmsa_ticket_result.first != 0 )
                            {
                                int status = -1;
                                cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket" );
                                if (domainless_user.find("awsdomainlessusersecret") !=
                                                           std::string::npos) {
                                    int pos = domainless_user.find(":");
                                    std::string domainlessUser = domainless_user.substr(pos + 1);
                                    status = get_user_krb_ticket(krb_ticket->domain_name,
                                                                  domainlessUser, cf_logger );
                                }
                                else if (domainless_user.find("kubedomainlessusersecret") !=
                                          std::string::npos) {
                                    int pos = domainless_user.find(":");
                                    std::string domainlessUser = domainless_user.substr(pos + 1);
                                    status = get_user_krb_ticket(krb_ticket->domain_name,
                                                                  domainlessUser, cf_logger );
                                    for ( auto kube_config_info :  kube_config_info_list )
                                    {
                                        std::map<std::string, std::list<std::string>>::iterator it;
                                        if(kube_config_info->secret_yaml_map.count(krb_ticket->krb_file_path)){
                                            std::map<std::string, std::list<std::string>>::iterator
                                                kube_it;
                                            for(kube_it=kube_config_info->secret_yaml_map.begin(); kube_it!=kube_config_info->secret_yaml_map
                                                                                                            .end(); ++kube_it){
                                                for (auto const& secret_path : kube_it->second) {
                                                    convert_secret_krb2kube(secret_path,
                                                                             krb_ticket->krb_file_path + "/krb5cc");
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    status = get_machine_krb_ticket( krb_ticket->domain_name,
                                                                         cf_logger );
                                    if (domainless_user.find("kubedomainlessusersecret") !=
                                         std::string::npos)
                                    {
                                        for ( auto kube_config_info : kube_config_info_list )
                                        {
                                            std::map<std::string, std::list<std::string>>::iterator
                                                it;
                                            if ( kube_config_info->secret_yaml_map.count(krb_ticket->krb_file_path ) )
                                            {
                                                std::map<std::string,
                                                         std::list<std::string>>::iterator kube_it;
                                                for ( kube_it = kube_config_info->secret_yaml_map
                                                                    .begin();
                                                      kube_it !=
                                                      kube_config_info->secret_yaml_map.end();
                                                      ++kube_it )
                                                {
                                                    for ( auto const& secret_path :
                                                          kube_it->second )
                                                    {
                                                        convert_secret_krb2kube(
                                                            secret_path,
                                                            krb_ticket->krb_file_path + "/krb5cc" );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if ( status < 0 )
                                {
                                    cf_logger.logger( LOG_ERR,
                                                      "Error %d: Cannot get machine krb ticket",
                                                      status );
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        cf_logger.logger( LOG_INFO, "gMSA ticket is at %s", krb_cc_name );
                        std::cout << "gMSA ticket is at " + krb_cc_name +
                                         " is not yet ready for "
                                         "renewal"
                                  << std::endl;
                    }
                }
            }
        }
        catch ( const std::exception& ex  )
        {
            std::cout << "Exception: '" << ex.what() << "'!" << std::endl;
            fprintf( stderr, SD_CRIT "failed to run the ticket renewal" );
            break;
        }
    }
    return -1;
}
