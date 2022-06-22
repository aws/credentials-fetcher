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
#include "cf-logger.h"

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
        };
}

/* TBD: Move to class and methods */
void parse_options(int argc, const char *argv[], creds_fetcher::Daemon cf_daemon);
void parse_config_file(std::string config_file, creds_fetcher::Daemon cf_daemon);
void initialize_krb();
void initialize_api();
void initialize_cache();
void initialize_timer();

#endif // _daemon_h_
