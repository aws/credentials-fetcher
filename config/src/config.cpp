#include "daemon.h"

/**
 * This function prints formatted help descriptions
 * @param long_options - option struct passed to getopt_log method
 * @param long_options - map of commnad line arg and its description
 */
void print_help( const struct option* long_options,
                 const std::map<std::string, std::string>& options_descriptions )
{
    std::cout << "Usage: " << std::endl;
    std::cout << "Runtime Environment Variables:" << std::endl; 
    std::cout << "CF_CRED_SPEC_FILE=<credential spec file>:<optional lease_id>" << std::endl; 
    std::cout << "\t<credential spec file>\tSet to a path of a json credential file." << std::endl; 
    std::cout << "\t<optional lease_id>\tUse an optional colon followed by a lease identifier (Default: " 
              << DEFAULT_CRED_FILE_LEASE_ID << ")"  << std::endl; 
    std::cout << "\nAllowed options" << std::endl;
    size_t max_option_length = 0;
    for ( const struct option* opt = long_options; opt->name != nullptr; ++opt )
    {
        size_t option_length =
            opt->has_arg == required_argument ? strlen( opt->name ) + 5 : strlen( opt->name ) + 2;
        if ( option_length > max_option_length )
        {
            max_option_length = option_length;
        }
    }
    for ( const struct option* opt = long_options; opt->name != nullptr; ++opt )
    {
        std::string opt_string;
        if ( opt->val != 0 )
        {
            opt_string = std::string( "--" ) + opt->name;
        }
        else
        {
            opt_string = std::string( "--" ) + opt->name;
        }
        std::string description;
        if ( options_descriptions.count( opt->name ) > 0 )
        {
            description = options_descriptions.at( opt->name );
        }
        else
        {
            description = opt->name;
        }
        std::cout << "  " << std::left << std::setw( max_option_length ) << opt_string << "\t"
                  << description << std::endl;
    }
}

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
        struct option long_options[] = { { "help", no_argument, nullptr, 'h' },
                                         { "self_test", no_argument, nullptr, 't' },
                                         { "verbosity", required_argument, nullptr, 'v' },
                                         { "aws_sm_secret_name", required_argument, nullptr, 's' },
                                         { "version", no_argument, nullptr, 'n' },
                                         { "healthcheck", no_argument, nullptr, 'c' },
                                         { nullptr, 0, nullptr, 0 } };
        std::map<std::string, std::string> options_descriptions{
            { "help", "produce help message" },
            { "self_test", "Run tests such as utf16 decode" },
            { "verbosity", "set verbosity level" },
            { "aws_sm_secret_name", "Name of secret containing username/password in AWS Secrets "
                                    "Manager (in same region)" },
            { "healthcheck", "health of credentials-fetcher" },
            { "version", "Version of credentials-fetcher" } };
        int option;
        int healthCheckResponse;
        while ( ( option = getopt_long( argc, (char* const*)argv, "htv:s:n", long_options, nullptr ) ) != -1 )
        {
            switch ( option )
            {
            case 'h':
                print_help( long_options, options_descriptions );
                return EXIT_FAILURE;
            case 't':
                std::cout << "run diagnostic set" << std::endl;
                cf_daemon.run_diagnostic = true;
                break;
            case 'v':
                std::cout << "Verbosity level was set to " << optarg << std::endl;
                break;
            case 's':
                cf_daemon.aws_sm_secret_name = optarg;
                std::cout << "Option selected for domainless operation, AWS secrets manager "
                             "secret-name = " << optarg << std::endl;
                break;
            case 'n':
                std::cout << CMAKE_PROJECT_VERSION << std::endl;
                return EXIT_FAILURE;
            case 'c':
                healthCheckResponse = HealthCheck("test");
                std::cout << healthCheckResponse << std::endl;
                if(healthCheckResponse != 0)
                {
                    exit(EXIT_FAILURE);
                }
                else
                {
                    exit(EXIT_SUCCESS);
                }

            default:
                std::cout << "Run with --help to see options" << std::endl;
                return EXIT_FAILURE;
            }
        }

        if ( cf_daemon.aws_sm_secret_name.empty() ) {
            cf_daemon.aws_sm_secret_name = retrieve_secret_from_ecs_config(domainless_gmsa_field);
            set_ecs_mode(true);
        }
    }
    catch ( const std::exception& ex )
    {
        std::cout << "Run with --help to see options" << std::endl;
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
