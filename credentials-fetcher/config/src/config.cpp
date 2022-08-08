#include "daemon.h"

/**
 * This function has options used to invoke the daemon such as
 * credentials-fetcherd --configfile path-to-file
 * @param argc - argc from command line input
 * @param argv - argv from command line input
 * @param cf_daemon - credentials fetcher parent object
 * @return status - 0 if successful
 */
int parse_options( int argc, const char* argv[], creds_fetcher::Daemon& cf_daemon )
{
    try
    {
        namespace po = boost::program_options;

        /* Declare the supported options */
        po::options_description desc( "Allowed options" );
        desc.add_options()( "help", "produce help message" ) /* TBD: Add help message description */
            ( "config_file", po::value<std::string>(),
                "config file location (default is "
                "/opt/etc/credentials-fetcher/config.json ), "
                "config.json (fill values as needed)"
                "{\n"
                "    \"krb_files_dir\": <root protected dir>\n"
                "    \"unix_socket_path\": <filepath inside krb files dir>\n"
                "    \"logging_dir: <path to logs dir>\n"
                "    \"domain_name\": \"<your domain name>\",\n"
                "    \"gmsa_account_name\": \"<your gmsa account>\"\n"
                "}")
                ("self_test",  "Run tests such as utf16 decode" )
                ("verbosity", po::value<int>(), "set verbosity level" );

        /**
         * Calls to store, parse_command_line and notify functions
         * cause the vm variable to contain all the options found on the command line
         */
        po::variables_map vm;
        po::store( po::parse_command_line( argc, argv, desc ), vm );
        po::notify( vm );

        if ( vm.count( "help" ) )
        {
            std::cout << desc << "\n";
            return EXIT_FAILURE;
        }

        cf_daemon.config_file = (char*)DEFAULT_CONFIG_FILE_LOCATION;
        if ( vm.count( "config_file" ) )
        {
            std::string value = vm["config_file"].as<std::string>();
            cf_daemon.config_file = new char[value.length() + 1];
            std::copy( value.begin(), value.end(), cf_daemon.config_file );
        }
        std::cout << "config file set to " << cf_daemon.config_file << std::endl;

        if ( vm.count( "verbosity" ) )
        {
            std::cout << "verbosity level was set to " << vm["verbosity"].as<int>() << std::endl;
        }

        if ( vm.count( "self_test" ) )
        {
            std::cout << "run diagnostic set" << std::endl;
            cf_daemon.run_diagnostic = true;
        }
    }
    catch ( const boost::program_options::error& ex )
    {
        std::cout << "Run with --help to see options" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * This function parses the daemon config file.
 * The config file is in json format.
 * @param config_file - location of file is in credentials-fetcher.spec as %config
 * @param cf_daemon - Credentials fetcher parent object
 * @return error - 0, if successful, -1 on error
 */
int parse_config_file( creds_fetcher::Daemon& cf_daemon )
{
    std::string config_file = cf_daemon.config_file;
    if ( config_file.empty() )
    {
        fprintf( stderr, SD_CRIT "config file is empty" );
        return -1;
    }
    try
    {
        namespace pt = boost::property_tree;
        pt::ptree root;
        pt::read_json( config_file, root );

        cf_daemon.krb_files_dir = root.get<std::string>( "krb_files_dir" );
        cf_daemon.logging_dir = root.get<std::string>( "logging_dir" );
        cf_daemon.unix_socket_path = root.get<std::string>( "unix_socket_path" );

        /**
     * Domain name and gmsa account are usually set in APIs.
     * The options below can be used as a test.
         */
        cf_daemon.domain_name = root.get<std::string>( "domain_name" );
        cf_daemon.gmsa_account_name = root.get<std::string>( "gmsa_account_name" );

        std::cout << "krb_files_dir = " << cf_daemon.krb_files_dir << std::endl;
        std::cout << "logging_dir = " << cf_daemon.logging_dir << std::endl;
        std::cout << "unix_socket_path = " << cf_daemon.unix_socket_path << std::endl;
    }
    catch ( ... )
    {
        std::cout << "config file parsing failed. check if the file exists at path " +
                         config_file <<
            std::endl;
        return -1;
    }

    return 0;
}
