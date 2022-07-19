#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
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
#include <sqlite3.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifndef _daemon_h_
#define _daemon_h_

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
    class krb_ticket_info
    {
      public:
        std::string lease_id;
        std::string krb_file_path;
        std::string service_account_name;
        std::string domain_name;
    };

    /*
     * Log the info/error logs with journalctl
     */
    class CF_logger
    {
        /* TBD:: Fill this later */

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
                sd_journal_print( level, fmt, logs... );
            }
        }
    };

    /*
     * cache to store the information about the tickets created
     */
    class CF_cache
    {
      public:
        sqlite3* db;
        char* errMsg = 0;
        int read_connection;
        std::string sql;
        std::list<creds_fetcher::krb_ticket_info>* krb_ticket_infos =
            new std::list<creds_fetcher::krb_ticket_info>;
    };

    class Daemon
    {
        /* TBD:: Fill this later */

      public: /* Add get methods */
        uint64_t watchdog_interval_usecs = 0;
        boost::program_options::variables_map vm;
        std::string config_file;
        std::string krb_files_dir;
        std::string unix_socket_path;
        std::string logging_dir;
        std::string domain_name;
        std::string gmsa_account_name;
        CF_logger cf_logger;
        CF_cache cf_cache;
        uint64_t krb_ticket_handle_interval = 10;
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
        uint8_t buf[1024];
        /* TBD:: Add remaining fields here */
    } blob_t;

} // namespace creds_fetcher

#define DEFAULT_CONFIG_FILE_LOCATION "/etc/credentials-fetcher/config.json"

/* TBD: Move to class and methods */
/**
 * Methods in auth module
 */
int generate_host_machine_krb_ticket( const char* krb_ccname = "" );
int get_machine_krb_ticket( std::string domain_name, creds_fetcher::CF_logger& cf_logger );
std::pair<int, std::string> get_gmsa_krb_ticket( std::string domain_name,
                                                 const std::string& gmsa_account_name,
                                                 const std::string& krb_cc_name,
                                                 const std::string& krb_files_dir,
                                                 creds_fetcher::CF_logger& cf_logger );
void krb_ticket_renewal( std::string principal, const std::string& krb_ccname );
void krb_ticket_creation( const char* ldap_uri_arg, const char* gmsa_account_name_arg,
                          const char* krb_ccname = "" );
bool is_ticket_ready_for_renewal( const char* krb_ccname = "" );
std::vector<std::string> delete_krb_tickets( std::string krb_files_dir, std::string lease_id );
void ltrim( std::string& s );
void rtrim( std::string& s );

/**
 * Methods in config module
 */
int parse_options( int argc, const char* argv[], creds_fetcher::Daemon& cf_daemon );
int parse_config_file( creds_fetcher::Daemon& cf_daemon );

/**
 * Methods in api module
 */
int RunGrpcServer( std::string unix_socket_path, std::string krb_file_path,
                   creds_fetcher::CF_logger& cf_logger );
int parse_cred_spec( std::string credspec_data, creds_fetcher::krb_ticket_info* krb_ticket_info );
std::string generate_lease_id();

/**
 * Methods in timer module
 */
void krb_ticket_handler( unsigned int interval, const char* ldap_uri_arg,
                         const char* gmsa_account_name_arg, const char* krb_ccname = "" );

/**
 * Methods in cache module
 */
void initialize_cache( creds_fetcher::CF_cache& cf_cache );

#endif // _daemon_h_
