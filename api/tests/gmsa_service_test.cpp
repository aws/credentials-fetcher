#include "daemon.h"
#include <boost/filesystem.hpp>

int parse_kube_config_json_test()
{
    std::string kubeconfig_file_path = "kubeconfig.json";

    std::list<creds_fetcher::kube_config_info*> result = parse_kube_config( kubeconfig_file_path,
                                                                            "/var/credentials-fetcher/krbdir" );

    if ( result.empty() || result.size() != 2 )
    {
        std::cout << "parsing kube config test failed" << std::endl;
        return EXIT_FAILURE;
    }

    for ( auto kube_config_info : result )
    {
        std::cout << kube_config_info->krb_ticket_info->service_account_name << std::endl;
        std::map<std::string, std::list<std::string>>::iterator it;
        for(it = kube_config_info->secret_yaml_map.begin(); it != kube_config_info->secret_yaml_map
                                                                        .end(); ++it){
            std::cout << it->first << '\n';
        }
    }
    std::cout << "parsing kube config test successful" << std::endl;
    return EXIT_SUCCESS;
}
