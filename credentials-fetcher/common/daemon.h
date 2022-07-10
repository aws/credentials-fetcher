#include <iostream>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <systemd/sd-daemon.h>
#include <unistd.h>
#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <ldap.h>
#include <krb5/krb5.h>
#include <thread>
#include <sqlite3.h>
#include <list>
#include "cf-logger.h"
#include "krb-ticket-info.h"
#include "../auth/kerberos/src/cf-krb.h"
#include "../timer/src/cf-timer.h"
#include "../cache/src/cf-cache.h"
#include "../api/src/cf-service.h"

#ifndef _daemon_h_
#define _daemon_h_

/*
 * This is a singleton class for the daemon, it is used
 * in method calls between the daemon and libraries.
 */
namespace creds_fetcher {
        class Daemon {
                /* TBD:: Fill this later */

                public: /* Add get methods */
                        uint64_t watchdog_interval_usecs = 0;
                        boost::program_options::variables_map vm;
                        std::string config_file;
                        std::string krb_files_dir;
                        std::string logging_dir;
                        std::string domain_name;
                        std::string gmsa_account_name;
                        CF_logger cf_logger;
                        CF_cache cf_cache;
                        uint64_t krb_ticket_handle_interval = 10;
        };
}

#define DEFAULT_CONFIG_FILE_LOCATION "/etc/credentials-fetcher/config.json"

/* TBD: Move to class and methods */
int parse_options(int argc, const char *argv[], creds_fetcher::Daemon &cf_daemon);
int parse_config_file(creds_fetcher::Daemon &cf_daemon);
//check the os for fedora
bool is_fedora();


#endif // _daemon_h_
