#include "daemon.h"

/**
 * This function has options used to invoke the daemon such as
 * credentials-fetcherd --configfile path-to-file
 * @param argc - argc from command line input
 * @param argv - argv from command line input
 * @param cf_daemon - credentials fetcher parent object
 * @return status - 0 if successful
 */
int parse_options(int argc, const char *argv[], creds_fetcher::Daemon &cf_daemon)
{
    namespace po = boost::program_options;

    /* Declare the supported options */
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message") /* TBD: Add help message description */
        ("config_file", po::value<std::string>(), "config file location")
        ("verbosity", po::value<int>(), "set verbosity level");

    /**
     * Calls to store, parse_command_line and notify functions
     * cause the vm variable to contain all the options found on the command line
     */
    po::store(po::parse_command_line(argc, argv, desc), cf_daemon.vm);
    po::notify(cf_daemon.vm);

    if (cf_daemon.vm.count("help")) {
        std::cout << desc << "\n";
        exit(EXIT_SUCCESS);
    }

    cf_daemon.config_file = DEFAULT_CONFIG_FILE_LOCATION;
    if (cf_daemon.vm.count("config_file")) {
        cf_daemon.config_file = cf_daemon.vm["config_file"].as<std::string>();
    }
    std::cout << "config file set to " << cf_daemon.config_file << std::endl;

    if (cf_daemon.vm.count("verbosity")) {
        std::cout << "verbosity level was set to "
            << cf_daemon.vm["verbosity"].as<int>() << std::endl;
    }

    return 0;
}

/**
 * This function parses the daemon config file.
 * The config file is in json format.
 * @param config_file - location of file is in credentials-fetcher.spec as %config
 * @param cf_daemon - Credentials fetcher parent object
 * @return error - 0, if successful, -1 on error
 */
int parse_config_file(creds_fetcher::Daemon &cf_daemon)
{
    std::string config_file = cf_daemon.config_file;
    if (config_file.empty()) {
        fprintf(stderr, SD_CRIT "config file is empty");
        return -1;
    }

    namespace pt = boost::property_tree;
    pt::ptree root;
    pt::read_json(config_file, root);

    cf_daemon.krb_files_dir = root.get<std::string>("krb_files_dir");
    cf_daemon.logging_dir = root.get<std::string>("logging_dir");
    cf_daemon.unix_socket_path = root.get<std::string>("unix_socket_path");

    /**
     * Domain name and gmsa account are usually set in APIs.
     * The options below can be used as a test.
     */
    cf_daemon.domain_name = root.get<std::string>("domain_name");
    cf_daemon.gmsa_account_name = root.get<std::string>("gmsa_account_name");

    std::cout << "krb_files_dir = " << cf_daemon.krb_files_dir << std::endl;
    std::cout << "logging_dir = " << cf_daemon.logging_dir << std::endl;
    std::cout << "unix_socket_path = " << cf_daemon.unix_socket_path << std::endl;

    return 0;
}
