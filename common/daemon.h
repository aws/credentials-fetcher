#include "config.h"
#include <json/json.h>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <glib.h>
#include <iostream>
#include <krb5/krb5.h>
#include <list>
#include <netinet/in.h>
#include <resolv.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <getopt.h>
#include <iomanip>
#include <map>
#include <algorithm>
#include <filesystem>

#if AMAZON_LINUX_DISTRO
#include <aws/core/Aws.h>
#endif

#ifndef _daemon_h_
#define _daemon_h_

#define DEFAULT_CRED_FILE_LEASE_ID "credspec"
#define LOG_FILE_PATH "/var/credentials-fetcher/logging/credentials-fetcher.log"

/*
 * This is a singleton class for the daemon, it is used
 * in method calls between the daemon and libraries.
 */
namespace creds_fetcher
{
    /**
     * TBD: move the classes to the corresponding header files
     */

    /**
    * krb_ticket_info defines the information of the kerberos ticket created
    */
    class krb_ticket_arn_mapping
    {
      public:
        std::string krb_file_path;
        std::string credential_spec_arn;
        std::string credential_domainless_user_arn;
    };

    /**
     * krb_ticket_info defines the information of the kerberos ticket created
     */
    class krb_ticket_info
    {
      public:
        std::string krb_file_path;
        std::string service_account_name;
        std::string domain_name;
        std::string domainless_user;
        std::string credspec_info;
        std::string distinguished_name;
    };

    /*
     * Log the info/error logs with journalctl
     */
    class CF_logger
    {
      public:
        int log_level = LOG_NOTICE;

        /* systemd uses log levels from syslog */
        void set_log_level( int _log_level )
        {
            log_level = _log_level;
        }

        template <typename... Logs> void logger( const int level, const char* fmt, Logs... logs )
        {
            if ( level >= log_level )
            {
                std::string logFmt = fmt;
                for (int i = 0; logFmt[i] != '\0'; ++i) {
                    if (logFmt[i] == '\n') {
                        logFmt[i] = ' '; // Replace '\n' with space
                    }
                }
                sd_journal_print( level, logFmt.c_str(), logs... );
            }
        }


        void init_file_logger ()
        {
            std::string log_file_path = LOG_FILE_PATH;
            freopen( log_file_path.c_str() , "a+", stdout );
        }
    };

    class Daemon
    {
        /* TBD:: Fill this later */

      public: /* Add get methods */
        uint64_t watchdog_interval_usecs = 0;
        char* config_file = NULL;
        std::string krb_files_dir;
        std::string cred_file;
        std::string unix_socket_dir;
        std::string logging_dir;
        std::string domain_name;
        std::string gmsa_account_name;
        CF_logger cf_logger;
        bool run_diagnostic = false;
        std::string aws_sm_secret_name; /* TBD:: Extend to other secret stores */
        // run ticket renewal every 10 minutes
        uint64_t krb_ticket_handle_interval = 10;
        volatile sig_atomic_t got_systemd_shutdown_signal;
    };

    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
    typedef struct blob_t_
    {
        uint16_t version;
        uint16_t reserved;
        uint32_t length;
        uint16_t current_password_offset;
        uint16_t previous_password_offset;
        uint16_t query_password_interval_offset;
        uint16_t unchanged_password_interval_offset;
#define BLOB_REMAINING_BUF_SIZE 1024 /* TBD:: Fix this, remaining buf size is variable */
#define GMSA_PASSWORD_SIZE 256       /* TBD: Get from parsed blob */
        uint8_t current_password[1024];
        /* TBD:: Add remaining fields here */
    } blob_t;

} // namespace creds_fetcher

/* TBD: Move to class and methods */
/**
 * Methods in auth module
 */
std::vector<std::string>  get_meta_data_file_paths(std::string krbdir);
std::string renew_gmsa_ticket( creds_fetcher::krb_ticket_info* krb_ticket, std::string domain_name,
                               std::string username, std::string password,
                               creds_fetcher::CF_logger& cf_logger  );
void truncate_log_files();
std::string getCurrentTime();
int generate_host_machine_krb_ticket( const char* krb_ccname = "" );
std::pair<int, std::string> exec_shell_cmd( std::string cmd );
std::pair<int, std::string> get_machine_krb_ticket( std::string domain_name, creds_fetcher::CF_logger& cf_logger );
std::pair<int, std::string> get_user_krb_ticket( std::string domain_name, std::string aws_sm_secret_name,
                                                 creds_fetcher::CF_logger& cf_logger );
std::pair<int, std::string> get_domainless_user_krb_ticket( std::string domain_name,
                                                            std::string username, std::string password,
                                                            creds_fetcher::CF_logger& cf_logger );

std::pair<int, std::string> get_gmsa_krb_ticket( std::string domain_name,
                                                 const std::string& gmsa_account_name,
                                                 const std::string& krb_cc_name,
                                                 creds_fetcher::CF_logger& cf_logger );

std::list<std::string> renew_kerberos_tickets_domainless( std::string krb_files_dir, std::string domain_name,
                                                          std::string username, std::string password,
                                                          creds_fetcher::CF_logger& cf_logger );

void krb_ticket_creation( const char* ldap_uri_arg, const char* gmsa_account_name_arg,
                          const char* krb_ccname = "" );

bool is_ticket_ready_for_renewal( creds_fetcher::krb_ticket_info* krb_ticket_info );

std::string get_ticket_expiration( std::string klist_ticket_info );

std::vector<std::string> delete_krb_tickets( std::string krb_files_dir, std::string lease_id );

void ltrim( std::string& s );

void rtrim( std::string& s );

// unit tests
//int test_utf16_decode();
int config_parse_test();
int read_meta_data_json_test();
int read_meta_data_invalid_json_test();
int write_meta_data_json_test();
int renewal_failure_krb_dir_not_found_test();

/**
 * Methods in config module
 */
int parse_options( int argc, const char* argv[], creds_fetcher::Daemon& cf_daemon );
bool isValidDomain(const std::string& value);
int HealthCheck(std::string serviceName);

int parse_config_file( creds_fetcher::Daemon& cf_daemon );
std::string retrieve_variable_from_ecs_config(std::string ecs_variable_name);
std::vector<std::string> split_string(std::string input_string, char delimiter);

/**
 * Methods in api module
 */
bool contains_invalid_characters_in_credentials( const std::string& value );
int RunGrpcServer( std::string unix_socket_dir, std::string krb_file_path,
                   creds_fetcher::CF_logger& cf_logger, volatile sig_atomic_t* shutdown_signal,
                   std::string aws_sm_secret_name );
bool contains_invalid_characters_in_ad_account_name( const std::string& value );

int parse_cred_spec( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info );

int parse_cred_spec_domainless( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info, creds_fetcher::krb_ticket_arn_mapping* krb_ticket_mapping );

int parse_cred_file_path(const std::string& cred_file_path, std::string& cred_file, std::string& cred_file_lease_id );

int ProcessCredSpecFile(std::string krb_files_dir, std::string credspec_filepath, creds_fetcher::CF_logger& cf_logger, std::string cred_file_lease_id);

std::string generate_lease_id();

void clearString(std::string& str);

#if AMAZON_LINUX_DISTRO
std::string retrieve_credspec_from_s3(std::string s3_arn, std::string region, Aws::Auth::AWSCredentials credentials,  bool test);
bool check_file_size_s3(std::string s3_arn, std::string region,
                         Aws::Auth::AWSCredentials credentials, bool test);
std::string get_caller_id(std::string region,
                           Aws::Auth::AWSCredentials credentials);
std::tuple<std::string, std::string,
           std::string> retrieve_credspec_from_secrets_manager(std::string sm_arn, std::string region, Aws::Auth::AWSCredentials credentials);

Aws::Auth::AWSCredentials get_credentials(std::string accessKeyId, std::string secretKey, std::string sessionToken);
#endif

/**
 * Methods in renewal module
 */
int krb_ticket_renew_handler( creds_fetcher::Daemon cf_daemon );

/**
 * Methods in metadata module
 */
bool contains_invalid_characters( const std::string& path );
std::list<creds_fetcher::krb_ticket_info*> read_meta_data_json( std::string file_path );

int write_meta_data_json( creds_fetcher::krb_ticket_info* krb_ticket_info,
                          std::string lease_id, std::string krb_files_dir );

int write_meta_data_json( std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list,
                          std::string lease_id, std::string krb_files_dir );

void set_ecs_mode(bool);
bool is_ecs_mode();


#endif // _daemon_h_
