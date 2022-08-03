#include "daemon.h"

int config_parse_test()
{
    creds_fetcher::Daemon cf_daemon;

    std::string config_file_path = "/etc/credentials-fetcher/config.json";
    cf_daemon.config_file = new char[config_file_path.length() + 1];
    std::copy( config_file_path.begin(), config_file_path.end(), cf_daemon.config_file );

    int result = parse_config_file( cf_daemon );
    if ( result != 0 )
    {
        std::cout << "config file parse test is failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "config file parse test is successful" << std::endl;
    return EXIT_SUCCESS;
}
