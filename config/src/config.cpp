#include "daemon.h"

#include <boost/program_options.hpp>

static std::string global_config_file_name( "/etc/credentials_fetcher.conf" );
static std::string grpc_mode( "grpc_mode" );
static std::string config_file_mode( "config_file_mode" );
static std::string kube_config_file_path( "/etc/credentials_fetcher_kubeconfig.json" );
static std::string default_krbdir_path( "/var/credentials_fetcher/krbdir" );
/* TBD: use constants for other strings in this file */

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
        namespace bp = boost::property_tree;

        /* Declare the supported options */
        po::options_description desc( "Allowed options" );
        desc.add_options()( "help", "produce help message" ) /* TBD: Add help message description */
            ( "self_test", "Run tests such as utf16 decode" )( "verbosity", po::value<int>(),
                                                               "set verbosity level" )(
                "aws_sm_secret_name", po::value<std::string>(), // TBD:: Extend to other stores
                "Name of secret containing username/password in AWS Secrets Manager (in same "
                "region)" );

        po::options_description fileOptions{ "File" };
        fileOptions.add_options()( "credentials_fetcher_mode", po::value<std::string>(),
                                   "credentials_fetcher_mode" );
        fileOptions.add_options()( "credentials_fetcher_krbdir_path", po::value<std::string>(),
                                   "credentials_fetcher_krbdir_path" );
        fileOptions.add_options()( "credentials_fetcher_krbfile_suffix", po::value<std::string>(),
                                   "credentials_fetcher_krbfile_suffix" );
        fileOptions.add_options()( "credentials_fetcher_fixed_lease_name_dir",
                                   po::value<std::string>(),
                                   "credentials_fetcher_fixed_lease_name_dir" );

        /**
         * Calls to store, parse_command_line and notify functions
         * cause the vm variable to contain all the options found on the command line
         */
        po::variables_map vm;
        po::store( po::parse_command_line( argc, argv, desc ), vm );
        po::notify( vm );

        std::ifstream ifs{ global_config_file_name };
        if ( ifs )
        {
            store( po::parse_config_file( ifs, fileOptions ), vm );
            po::notify( vm );
            std::string msg = "Using global config file " + global_config_file_name;
            std::cout << msg << std::endl;
        }

        if ( vm.count( "credentials_fetcher_fixed_lease_name_dir" ) )
        {
            cf_daemon.fixed_lease_name_dir =
                vm["credentials_fetcher_fixed_lease_name_dir"].as<std::string>();
            std::cout << "Using fixed name dir = " + cf_daemon.fixed_lease_name_dir << std::endl;
        }

        if ( vm.count( "credentials_fetcher_mode" ) )
        {
            std::string msg =
                "credentials_fetcher_mode = " + vm["credentials_fetcher_mode"].as<std::string>();
            std::cout << msg << std::endl;
            std::string eks_mode = "\"" + config_file_mode + "\"";
            if ( vm["credentials_fetcher_mode"].as<std::string>() == eks_mode )
            {
                msg = "From global config file, credentials_fetcher_mode = " +
                      vm["credentials_fetcher_mode"].as<std::string>();
                std::cout << msg << std::endl;
                cf_daemon.use_kube = true;
                cf_daemon.kube_config_file_path = kube_config_file_path;
                std::string msg =
                    "From global config file, credentials_fetcher_kubeconfig_path = " +
                    cf_daemon.kube_config_file_path;
                std::cout << msg << std::endl;
                if ( cf_daemon.fixed_lease_name_dir.empty() )
                {
                    cf_daemon.fixed_lease_name_dir = "eks_configuration";
                }
            }

            cf_daemon.krb_files_dir = default_krbdir_path;
            if ( vm.count( "credentials_fetcher_krbdir_path" ) )
            {
                cf_daemon.krb_files_dir = vm["credentials_fetcher_krbdir_path"].as<std::string>();
            }
            msg = "Setting credentials_fetcher_krbdir_path as " + cf_daemon.krb_files_dir;
            std::cout << msg << std::endl;

            if ( vm.count( "credentials_fetcher_krbfile_suffix" ) )
            {
                cf_daemon.krb_file_suffix =
                    vm["credentials_fetcher_krbfile_suffix"].as<std::string>();
                std::string msg =
                    "Setting credentials_fetcher_krbfile_suffix as " + cf_daemon.krb_file_suffix;
                std::cout << msg << std::endl;
            }

            if ( vm.count( "help" ) )
            {
                std::cout << desc << "\n";
                return EXIT_FAILURE;
            }

            if ( vm.count( "verbosity" ) )
            {
                std::cout << "verbosity level was set to " << vm["verbosity"].as<int>()
                          << std::endl;
            }

            if ( vm.count( "self_test" ) )
            {
                std::cout << "run diagnostic set" << std::endl;
                cf_daemon.run_diagnostic = true;
            }

            if ( vm.count( "aws_sm_secret_name" ) ) // TBD:: Extend to other stores
            {
                cf_daemon.aws_sm_secret_name = vm["aws_sm_secret_name"].as<std::string>();
                std::cout << "Option selected for domainless operation, AWS secrets manager "
                             "secret-name = "
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
    }
    catch ( const boost::program_options::error& ex )
    {
        std::cout << "Run with --help to see options" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
