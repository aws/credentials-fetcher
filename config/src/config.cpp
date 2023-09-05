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
        std::string domainless_gmsa_field( "CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA" );
        namespace po = boost::program_options;

        /* Declare the supported options */
        po::options_description desc( "Runtime Environment Variables:\n\tCF_CRED_FILE\tOptionally set to a path of a json credential file instead of using gRPC.\n\nAllowed options" );
        desc.add_options()( "help", "produce help message" ) /* TBD: Add help message description */
            ( "self_test", "Run tests such as utf16 decode" )( "verbosity", po::value<int>(),
                                                               "set verbosity level" )(
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
        std::string aws_sm_secret_name = retrieve_secret_from_ecs_config(domainless_gmsa_field);
        cf_daemon.aws_sm_secret_name = aws_sm_secret_name;
    }
    catch ( const boost::program_options::error& ex )
    {
        std::cout << "Run with --help to see options" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
