#include <iostream>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <systemd/sd-daemon.h>
#include <unistd.h>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
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

#ifndef _daemon_h_
#define _daemon_h_

/*
 * This is a singleton class for the daemon, it is used
 * in method calls between the daemon and libraries.
 */
namespace creds_fetcher {
        class Daemon {
                /* TBD:: Fill this later */

                public:
                        uint64_t watchdog_interval_usecs = 0;
                        boost::program_options::variables_map vm;
                        std::string config_file;
                        std::string krb_files_dir;
                        std::string logging_dir;
                        CF_logger cf_logger;
                        CF_cache cf_cache;
                        uint64_t krb_ticket_handle_interval = 10;
        };
}

/* TBD: Move to class and methods */
void parse_options(int argc, const char *argv[], creds_fetcher::Daemon cf_daemon);
void parse_config_file(std::string config_file, creds_fetcher::Daemon cf_daemon);
void initialize_krb();
void initialize_api();

#endif // _daemon_h_
