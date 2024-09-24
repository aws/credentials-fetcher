#include "daemon.h"
#include "util.hpp"
#include <cstdio>
#include <dirent.h>
#include <filesystem>
#include <iostream>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <sys/types.h>

const std::vector<char> invalid_characters = { '&',  '|', ';', ':',  '$', '*', '?', '<',
                                               '>',  '!', ' ', '\\', '.', ']', '[', '+',
                                               '\'', '`', '~', '}',  '{', '"', ')', '(' };

const std::string install_path_for_decode_exe = "/usr/sbin/credentials_fetcher_utf16_private.exe";

const std::string install_path_for_aws_cli = "/usr/bin/aws";

/**
 * This function generates the kerberos ticket for the host machine.
 * It uses machine keytab located at /etc/krb5.keytab to generate the ticket.
 * @param cf_daemon - parent daemon object
 * @return error-code - 0 if successful
 */
std::pair<int, std::string> generate_krb_ticket_from_machine_keytab( std::string domain_name,
                                                                     CF_logger& cf_logger )
{
    std::pair<int, std::string> result;

    result = Util::is_hostname_cmd_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    result = Util::is_hostname_cmd_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    result = Util::is_realm_cmd_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    result = Util::is_kinit_cmd_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    result = Util::is_ldapsearch_cmd_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    result = Util::is_decode_exe_present();
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    /**
     ** Machine principal is of the format 'EC2AMAZ-Q5VJZQ$'@CONTOSO.COM
     **/
    std::pair<int, std::string> machine_principal =
        Util::get_machine_principal( domain_name, cf_logger );
    if ( result.first != 0 )
    {
        std::cerr << "ERROR: " << __func__ << ":" << __LINE__ << " invalid machine principal"
                  << std::endl;
        std::string err_msg = "ERROR: invalid machine principal";
        cf_logger.logger( LOG_ERR, err_msg.c_str() );
        result = std::make_pair( -1, err_msg );
        return result;
    }

    result = Util::execute_kinit_in_domain_joined_case( machine_principal.second );
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, result.second.c_str() );
        return result;
    }

    return result;
}

/**
 * This function fetches the gmsa password and creates a krb ticket
 * It uses the existing krb ticket of machine to run ldap query over
 * kerberos and do the appropriate UTF decoding.
 *
 * @param domain_name - Like 'contoso.com'
 * @param gmsa_account_name - Like 'webapp01'
 * @param krb_cc_name - Like '/var/credentials_fetcher/krb_dir/krb5_cc'
 * @param cf_logger - log to systemd daemon
 * @return result code and kinit log, 0 if successful, -1 on failure
 */
std::pair<int, std::string> fetch_gmsa_password_and_create_krb_ticket(
    std::string domain_name, const std::string& gmsa_account_name, const std::string& krb_cc_name,
    std::string distinguished_name, CF_logger& cf_logger )
{
    std::vector<std::string> results;

    if ( domain_name.empty() || gmsa_account_name.empty() )
    {
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d null args", __func__, __LINE__ );
        std::string err_msg = std::string( "domain_name " + domain_name + " or gmsa_account_name " +
                                           gmsa_account_name + " is empty" );
        return std::make_pair( -1, err_msg );
    }

    if ( distinguished_name.empty() )
    {
        if ( getenv( ENV_CF_GMSA_OU ) == NULL )
        {
        /**
         * ldapsearch -H ldap://<fqdn> -b 'CN=webapp01,CN=Managed Service
         *   Accounts,DC=contoso,DC=com' -s sub  "(objectClass=msDs-GroupManagedServiceAccount)"
         *   msDS-ManagedPassword
         */
            results = Util::split_string( domain_name, '.' );
            std::string base_dn;
            for ( auto& result : results )
            {
                 base_dn += "DC=" + result + ",";
            }
            base_dn.pop_back(); // Remove last comma
            distinguished_name = std::string( ",CN=Managed Service Accounts," ); //default value
            //  The environment variable CF_GMSA_OU default value is "CN=Managed Service Accounts"
            distinguished_name = "CN=" + gmsa_account_name + "," + distinguished_name + base_dn;
        }
        else
        {
            distinguished_name = std::string( getenv( ENV_CF_GMSA_OU ) );
        }
    }

    std::pair<int, std::string> ldap_search_result;

    std::vector<std::string> fqdn_list_result = Util::get_FQDN_list( domain_name );
    for ( auto fqdn : fqdn_list_result )
    {
        ldap_search_result =
            Util::execute_ldapsearch( gmsa_account_name, distinguished_name, fqdn );
        if ( ldap_search_result.first == 0 )
        {
            std::size_t pos = ldap_search_result.second.find( "msDS-ManagedPassword" );
            std::string log_str = ldap_search_result.second.substr( 0, pos );
            log_str = "ldapsearch successful with FQDN = " + fqdn + ", cmd = " + log_str + "\n";
            std::cerr << log_str << std::endl;
            cf_logger.logger( LOG_INFO, log_str.c_str() );
            break;
        }
        else
        {
            std::string log_str =
                "ldapsearch failed with FQDN = " + fqdn + ldap_search_result.second.c_str();
            std::cerr << log_str << std::endl;
            cf_logger.logger( LOG_INFO, log_str.c_str() );
        }
    }
    fqdn_list_result.clear();

    if ( ldap_search_result.first != 0 ) // ldapsearch did not work in any FQDN
    {
        return std::make_pair( -1, std::string( "" ) );
    }

    std::pair<size_t, void*> password_found_result =
        Util::find_password( ldap_search_result.second );
    OPENSSL_cleanse( (void*)ldap_search_result.second.c_str(),
                     strlen( ldap_search_result.second.c_str() ) );

    if ( password_found_result.first == 0 || password_found_result.second == nullptr )
    {
        std::string log_str = Util::getCurrentTime() + '\t' + "ERROR: Password not found";
        std::cerr << log_str << std::endl;
        cf_logger.logger( LOG_ERR, log_str.c_str() );
        return std::make_pair( -1, log_str );
    }

    blob_t* blob = ( (blob_t*)password_found_result.second );
    auto* blob_password = (uint8_t*)blob->current_password;

    std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string default_principal = "'" + gmsa_account_name + "$'" + "@" + domain_name;

    /* Pipe password to the utf16 decoder and kinit */
    std::string kinit_cmd = std::string( "dotnet " ) + std::string( install_path_for_decode_exe ) +
                            std::string( " | kinit " ) + std::string( " -c " ) + krb_cc_name +
                            " -V " + default_principal;
    std::cerr << Util::getCurrentTime() << '\t' << "INFO:" << kinit_cmd << std::endl;
    FILE* fp = popen( kinit_cmd.c_str(), "w" );
    if ( fp == nullptr )
    {
        perror( "kinit failed" );
        OPENSSL_cleanse( password_found_result.second, password_found_result.first );
        OPENSSL_free( password_found_result.second );
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d kinit failed", __func__, __LINE__ );
        std::cerr << Util::getCurrentTime() << '\t' << "ERROR: kinit failed" << std::endl;
        return std::make_pair( -1, std::string( "kinit failed" ) );
    }
    fwrite( blob_password, 1, GMSA_PASSWORD_SIZE, fp );
    int error_code = pclose( fp );

    // kinit output
    std::string log_str = Util::getCurrentTime() + '\t' +
                          "INFO: kinit return value = " + std::to_string( error_code );
    std::cerr << log_str << std::endl;
    cf_logger.logger( LOG_ERR, log_str.c_str() );

    OPENSSL_cleanse( password_found_result.second, password_found_result.first );

    return std::make_pair( error_code, krb_cc_name );
}

/**
 * Parses the string that is a result of the klist command for the ticket experation date and time
 * @param klist_ticket_info  - String output of the klist command to parse
 * @return - returns the date and time of the ticket experation otherwise an empty string
 */
std::string get_ticket_expiration( std::string klist_ticket_info, CF_logger& cf_logger )
{
    /*
     * Ticket cache: KEYRING:persistent:1000:1000
     * Default principal: admin@CUSTOMERTEST.LOCAL

    * Valid starting       Expires              Service principal
        * 12/04/2023 19:39:06  12/05/2023 05:39:06  krbtgt/CUSTOMERTEST.LOCAL@CUSTOMERTEST.LOCAL
                                                                               * renew until
    12/11/2023 19:39:04
        */

    std::string any_regex( ".+" );
    std::string day_regex( "[0-9]{2}" );
    std::string month_regex( "[0-9]{2}" );
    std::string year_in_four_digits_regex( "[0-9]{4}" );
    std::string year_in_two_digits_regex( "[0-9]{2}" );
    std::string time_regex( "([0-9]{2}:[0-9]{2}:[0-9]{2})" );
    std::string separator_regex( "[/]{1}" );
    std::string space_regex( "[ ]+" );
    std::string left_paren_regex( "(" );
    std::string right_paren_regex( ")" );
    std::string krbtgt_regex( "krbtgt" );

    std::string date_regex = left_paren_regex + day_regex + separator_regex + month_regex +
                             separator_regex + year_in_four_digits_regex + right_paren_regex;

    /* 12/04/2023 19:39:06  12/05/2023 05:39:06  krbtgt/CUSTOMERTEST.LOCAL@CUSTOMERTEST.LOCAL */
    std::string expires_regex = date_regex + space_regex + time_regex + space_regex + date_regex +
                                space_regex + time_regex + space_regex + krbtgt_regex;

    std::string regex_pattern( expires_regex );
    std::regex pattern( expires_regex );
    std::smatch expires_match;

    if ( !std::regex_search( klist_ticket_info, expires_match, pattern ) )
    {
        // Retry with 2 digit year
        /* 12/04/23 21:58:51  12/05/23 07:58:51  krbtgt/CUSTOMERTEST.LOCAL@CUSTOMERTEST.LOCAL */
        date_regex = left_paren_regex + day_regex + separator_regex + month_regex +
                     separator_regex + year_in_two_digits_regex + right_paren_regex;
        expires_regex = date_regex + space_regex + time_regex + space_regex + date_regex +
                        space_regex + time_regex + space_regex + krbtgt_regex;
        pattern = expires_regex;
        if ( !std::regex_search( klist_ticket_info, expires_match, pattern ) )
        {
            std::string log_str =
                "Unable to parse klist for ticket expiration: " + klist_ticket_info;
            std::cerr << log_str << std::endl;
            cf_logger.logger( LOG_ERR, log_str.c_str() );
            return std::string( "" );
        }
    }

    /*
     * From example above:
     * 12/04/2023
     * 19:39:06
     * 12/05/2023
     * 05:39:06
     */
    std::string klist_valid_date;
    std::string klist_valid_time;
    std::string klist_expires_date;
    std::string klist_expires_time;
    for ( auto it = expires_match.cbegin(); it != expires_match.cend(); it++ )
    {
        // First one is the full string
        if ( it != expires_match.cbegin() )
        {
            if ( klist_valid_date.empty() )
            {
                klist_valid_date = *it;
                continue;
            }
            if ( klist_valid_time.empty() )
            {
                klist_valid_time = *it;
                continue;
            }
            if ( klist_expires_date.empty() )
            {
                klist_expires_date = *it;
                continue;
            }
            if ( klist_expires_time.empty() )
            {
                klist_expires_time = *it;
                continue;
            }
        }
    }

    std::string log_str = "klist expires date = " + klist_expires_date + " " + klist_expires_time;
    std::cerr << log_str << std::endl;
    cf_logger.logger( LOG_INFO, log_str.c_str() );
    return klist_expires_date + " " + klist_expires_time;
}

/**
 * Checks if the given ticket needs renewal or recreation
 * @param krb_cc_name  - Like '/var/credentials_fetcher/krb_dir/krb5_cc'
 * @return - is renewal needed - true or false
 */

bool is_ticket_ready_for_renewal( krb_ticket_info_t* krb_ticket_info, CF_logger& cf_logger )
{
    std::string cmd = "export KRB5CCNAME=" + krb_ticket_info->krb_file_path + " &&  klist";
    std::pair<int, std::string> krb_ticket_info_result = Util::exec_shell_cmd( cmd );
    if ( krb_ticket_info_result.first != 0 )
    {
        // we need to check if meta file exists to recreate the ticket
        std::cerr << Util::getCurrentTime() << '\t' << "ERROR: klist failed for command " << cmd
                  << std::endl;
        return false;
    }

    std::vector<std::string> results;

    results = Util::split_string( krb_ticket_info_result.second, '#' );
    std::string renew_until = "renew until";
    bool is_ready_for_renewal = false;

    for ( auto& result : results )
    {
        auto found = result.find( renew_until );
        if ( found != std::string::npos )
        {
            std::string renewal_date_time;

            renewal_date_time = get_ticket_expiration( result, cf_logger );

            char renewal_date[80];
            char renewal_time[80];

            sscanf( renewal_date_time.c_str(), "%79s %79s", renewal_date, renewal_time );

            renew_until = std::string( renewal_date ) + " " + std::string( renewal_time );
            // trim extra spaces
            Util::ltrim( renew_until );
            Util::rtrim( renew_until );

            // next renewal time for the ticket
            struct tm tm;

            // if the string is not date time format, return false
            if ( strptime( renew_until.c_str(), "%m/%d/%Y %T", &tm ) == NULL )
                return false;

            std::time_t next_renewal_time = mktime( &tm );

            // get the current system time
            std::time_t t = std::time( NULL );
            std::tm* now = std::localtime( &t );
            std::time_t current_time = mktime( now );

            // calculate the time difference in hours
            double hours = std::difftime( next_renewal_time, current_time ) / SECONDS_IN_HOUR;

            // check of the ticket need to be renewed
            if ( hours <= RENEW_TICKET_HOURS )
            {
                is_ready_for_renewal = true;
            }
            break;
        }
    }

    return is_ready_for_renewal;
}

/**
 * This function does the ticket renewal in domainless mode.
 * @param krb_files_dir
 * @param domain_name
 * @param username
 * @param password
 */
std::list<std::string> renew_kerberos_tickets_domainless( std::string krb_files_dir,
                                                          std::string domain_name,
                                                          std::string username,
                                                          std::string password,
                                                          CF_logger& cf_logger )
{
    std::list<std::string> renewed_krb_ticket_paths;
    // identify the metadata files in the krb directory
    std::vector<std::string> metadatafiles = get_meta_data_file_paths( krb_files_dir );

    // read the information of service account from the files
    for ( auto file_path : metadatafiles )
    {
        std::list<krb_ticket_info_t*> krb_ticket_info_list = read_meta_data_json( file_path );

        // refresh the kerberos tickets for the service accounts, if tickets ready for
        // renewal
        for ( auto krb_ticket : krb_ticket_info_list )
        {
            std::string domainlessuser = krb_ticket->domainless_user;
            if ( !username.empty() && username == domainlessuser )
            {
                std::string renewed_ticket_path =
                    renew_gmsa_ticket( krb_ticket, domain_name, username, password, cf_logger );

                if ( !renewed_krb_ticket_paths.empty() )
                {
                    renewed_krb_ticket_paths.push_back( renewed_ticket_path );
                }
            }
        }
    }

    return renewed_krb_ticket_paths;
}

/**
 * get metadata file info
 * @param krbdir - location for kerberos directory
 */
std::vector<std::string> get_meta_data_file_paths( std::string krbdir )
{
    // identify the metadata files in the krb directory
    std::vector<std::string> metadatafiles;
    for ( std::filesystem::recursive_directory_iterator end, dir( krbdir ); dir != end; ++dir )
    {
        auto path = dir->path();
        if ( std::filesystem::is_regular_file( path ) )
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
    return metadatafiles;
}

/**
 * renew gmsa kerberos tickets
 * @param krb_ticket_info - kerberos ticket info
 * @param domain_name
 * @param username
 * @param password
 * @param cf_logger - credentials fetcher logger
 */
std::string renew_gmsa_ticket( krb_ticket_info_t* krb_ticket, std::string domain_name,
                               std::string username, std::string password, CF_logger& cf_logger )
{
    std::string renewed_krb_ticket_path;
    std::pair<int, std::string> gmsa_ticket_result;
    std::string krb_cc_name = krb_ticket->krb_file_path;

    // gMSA kerberos ticket generation needs to have ldap over kerberos
    // if the ticket exists for the machine/user already reuse it for getting gMSA password else
    // retry the ticket creation again after generating user/machine kerberos ticket
    int num_retries = 2;
    for ( int i = 0; i < num_retries; i++ )
    {
        gmsa_ticket_result = fetch_gmsa_password_and_create_krb_ticket(
            krb_ticket->domain_name, krb_ticket->service_account_name, krb_cc_name,
            krb_ticket->distinguished_name, cf_logger );
        if ( gmsa_ticket_result.first != 0 )
        {
            if ( i == 0 )
            {
                cf_logger.logger( LOG_WARNING,
                                  "WARNING: Cannot get gMSA krb ticket "
                                  "because of expired user/machine ticket, "
                                  "will be retried automatically, service_account_name = %s",
                                  krb_ticket->service_account_name.c_str() );
            }
            else
            {
                cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket using account %s",
                                  krb_ticket->service_account_name.c_str() );

                std::cerr << Util::getCurrentTime() << '\t'
                          << "ERROR: Cannot get gMSA krb ticket using account" << std::endl;
            }
            // if tickets are created in domainless mode
            std::string domainless_user = krb_ticket->domainless_user;
            if ( !domainless_user.empty() && domainless_user == username )
            {
                std::pair<int, std::string> status =
                    Util::generate_krb_ticket_using_username_and_password( domain_name, username,
                                                                           password, cf_logger );

                if ( status.first < 0 )
                {
                    cf_logger.logger( LOG_ERR, "ERROR %d: Cannot get user krb ticket", status );
                    std::cerr << Util::getCurrentTime() << '\t'
                              << "ERROR: Cannot get user krb ticket" << std::endl;
                }
            }
            else
            {
                break;
            }
        }
        else
        {
            renewed_krb_ticket_path = krb_cc_name;
            i++;
        }
    }

    return renewed_krb_ticket_path;
}

/**
 * delete kerberos ticket corresponding to lease id
 * @param krb_files_dir - path to kerberos directory
 * @param lease_id - lease_id associated to kerberos tickets
 * @return - vector of kerberos deleted paths
 */
std::vector<std::string> delete_krb_tickets( std::string krb_files_dir, std::string lease_id )
{
    std::vector<std::string> delete_krb_ticket_paths;
    if ( lease_id.empty() || krb_files_dir.empty() )
        return delete_krb_ticket_paths;

    std::string krb_tickets_path = krb_files_dir + "/" + lease_id;

    DIR* curr_dir;
    struct dirent* file;
    // open the directory
    curr_dir = opendir( krb_tickets_path.c_str() );
    try
    {
        if ( curr_dir )
        {
            while ( ( file = readdir( curr_dir ) ) != NULL )
            {
                std::string filename = file->d_name;
                if ( !filename.empty() && filename.find( "_metadata" ) != std::string::npos )
                {
                    std::string file_path = krb_tickets_path + "/" + filename;
                    std::list<krb_ticket_info_t*> krb_ticket_info_list =
                        read_meta_data_json( file_path );

                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        std::string krb_file_path = krb_ticket->krb_file_path;
                        std::string cmd = "export KRB5CCNAME=" + krb_file_path + " && kdestroy";

                        std::pair<int, std::string> krb_ticket_destroy_result =
                            Util::exec_shell_cmd( cmd );
                        if ( krb_ticket_destroy_result.first == 0 )
                        {
                            delete_krb_ticket_paths.push_back( krb_file_path );
                        }
                        else
                        {
                            // log ticket deletion failure
                            std::cerr << Util::getCurrentTime() << '\t'
                                      << "Delete kerberos ticket "
                                         "failed" +
                                             krb_file_path
                                      << std::endl;
                        }
                    }
                }
            }
            // close directory
            closedir( curr_dir );

            // finally delete lease file and directory
            std::filesystem::remove_all( krb_tickets_path );
        }
    }
    catch ( ... )
    {
        std::cerr << Util::getCurrentTime() << '\t'
                  << "Delete kerberos ticket "
                     "failed"
                  << std::endl;
        closedir( curr_dir );
        return delete_krb_ticket_paths;
    }
    return delete_krb_ticket_paths;
}
