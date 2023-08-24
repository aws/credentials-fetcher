#include "daemon.h"

#include <boost/program_options.hpp>

static std::string global_config_file_name( "/etc/credentials_fetcher.conf" );
static std::string credentials_fetcher_mode_key( "credentials_fetcher_mode" );
static std::string domain_joined_and_grpc_mode( "domain_joined_and_grpc_mode" );
static std::string domain_joined_and_eks_mode( "domain_joined_and_eks_mode" );
static std::string kubeconfig_path_key( "credentials_fetcher_kubeconfig_path" );
static std::string config_file_mode_key( "config_file_mode" );
static std::string krb_dir_path_mode( "krb_dir_path_mode" );
static std::string config_krb_path_key( "credentials_fetcher_krbdir_path" );
static std::string krbdir( "/var/credentials-fetcher/krbdir" );

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
        fileOptions.add_options()( "credentials_fetcher_kubeconfig_path", po::value<std::string>(),
                                   "credentials_fetcher_kubeconfig_path" );
        fileOptions.add_options()( "config_file_mode", po::value<std::string>(),
                                   "config_file_mode" );

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

        if ( vm.count( "credentials_fetcher_mode" ) )
        {
            std::string msg =
                "credentials_fetcher_mode = " + vm["credentials_fetcher_mode"].as<std::string>();
            std::cout << msg << std::endl;
            std::string mode = "\"" + domain_joined_and_eks_mode + "\"";
            if ( vm["credentials_fetcher_mode"].as<std::string>() == mode )
            {
                msg = "From global config file, credentials_fetcher_mode = " +
                      vm["credentials_fetcher_mode"].as<std::string>();
                std::cout << msg << std::endl;
                cf_daemon.use_kube = true;
                if ( vm.count( "credentials_fetcher_kubeconfig_path" ) )
                {
                    cf_daemon.kube_config_file_path =
                        vm["credentials_fetcher_kubeconfig_path"].as<std::string>();
                    cf_daemon.kube_config_file_path.erase( cf_daemon.kube_config_file_path.begin(),
                                                           cf_daemon.kube_config_file_path.begin() +
                                                               1 );
                    cf_daemon.kube_config_file_path.erase( cf_daemon.kube_config_file_path.end() -
                                                               1,
                                                           cf_daemon.kube_config_file_path.end() );
                    std::string msg =
                        "From global config file, credentials_fetcher_kubeconfig_path = " +
                        cf_daemon.kube_config_file_path;
                    std::cout << msg << std::endl;
                }
            }

            if ( vm.count( "config_file_mode" ) )
            {
                std::string msg = "config_file_mode = " + vm["config_file_mode"].as<std::string>();
                std::cout << msg << std::endl;
                std::string mode = "\"" + krb_dir_path_mode + "\"";
                if ( vm["config_file_mode"].as<std::string>() == mode )
                {
                    msg = "From global config file, config_file_mode = " +
                          vm["config_file_mode"].as<std::string>();
                    std::cout << msg << std::endl;
                    cf_daemon.use_kube = true;
                    if ( vm.count( "credentials_fetcher_krbdir_path" ) )
                    {
                        cf_daemon.krb_files_dir =
                            vm["credentials_fetcher_krbdir_path"].as<std::string>();
                        cf_daemon.kube_config_file_path.erase(
                            cf_daemon.krb_files_dir.begin(), cf_daemon.krb_files_dir.begin() + 1 );
                        cf_daemon.kube_config_file_path.erase( cf_daemon.krb_files_dir.end() - 1,
                                                               cf_daemon.krb_files_dir.end() );
                        std::string msg =
                            "From global config file, credentials_fetcher_krbdir_path = " +
                            cf_daemon.krb_files_dir;
                        std::cout << msg << std::endl;
                    }
                }
            }
        }

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
