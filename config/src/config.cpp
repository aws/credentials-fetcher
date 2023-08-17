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
    const char* ecs_config_file_name = "/etc/ecs/ecs.config"; // TBD:: Add commandline if needed
    std::string domainless_gmsa_field( "CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA" );

    try
    {
        namespace po = boost::program_options;

        /* Declare the supported options */
        po::options_description desc( "Allowed options" );
        desc.add_options()( "help", "produce help message" ) /* TBD: Add help message description */
            ( "self_test", "Run tests such as utf16 decode")
                ("use_kube", po::value<std::string>(), "update the config file located /etc/credentials_fetcher_kubeconfig.json"
                               ".json" )
	        ( "verbosity", po::value<int>(), "set verbosity level" )(
                "aws_sm_secret_name", po::value<std::string>(), // TBD:: Extend to other stores
                "Name of secret containing username/password in AWS Secrets Manager (in same "
                "region)" );

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

        if ( vm.count( "verbosity" ) )
        {
            std::cout << "verbosity level was set to " << vm["verbosity"].as<int>() << std::endl;
        }

        if ( vm.count( "use_kube" ) )
        {
            cf_daemon.kube_config_file_path = vm["use_kube"].as<std::string>();;
            cf_daemon.krb_files_dir = "/var/credentials-fetcher/krbdir";
            std::cout
                << "Option selected for kube apply, path to kube config"
                <<  cf_daemon.kube_config_file_path << std::endl;
        }

        if ( vm.count( "self_test" ) )
        {
            std::cout << "run diagnostic set" << std::endl;
            cf_daemon.run_diagnostic = true;
        }

        if ( vm.count( "aws_sm_secret_name" ) ) // TBD:: Extend to other stores
        {
            cf_daemon.aws_sm_secret_name = vm["aws_sm_secret_name"].as<std::string>();
            std::cout
                << "Option selected for domainless operation, AWS secrets manager secret-name = "
                << cf_daemon.aws_sm_secret_name << std::endl;
        }

        std::ifstream config_file( ecs_config_file_name );
        std::string line;
        std::vector<std::string> results;

        while ( std::getline( config_file, line ) )
        {
            // TBD: Error handling for incorrectly formatted /etc/ecs/ecs.config
            boost::split( results, line, []( char c ) { return c == '='; } );
            std::string key = results[0];
            std::string value = results[1];
            if ( domainless_gmsa_field.compare( key ) == 0 )
            {
                value.erase( std::remove( value.begin(), value.end(), '"' ), value.end() );
                std::cout << "Using " << value << " for domainless gMSA" << std::endl;
                cf_daemon.aws_sm_secret_name = value;
            }
        }
    }
    catch ( const boost::program_options::error& ex )
    {
        std::cout << "Run with --help to see options" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
