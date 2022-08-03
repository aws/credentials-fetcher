#include "daemon.h"
#include <boost/filesystem.hpp>

int read_meta_data_json_test()
{
    std::string metadata_file_path = "metadata_sample.json";

    std::list<creds_fetcher::krb_ticket_info*> result = read_meta_data_json( metadata_file_path );

    if ( result.empty() || result.size() != 2 )
    {
        std::cout << "reading meta data file test is failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "read meta data file test is successful" << std::endl;
    return EXIT_SUCCESS;
}

int write_meta_data_json_test()
{
    std::string metadata_file_path = "metadata_sample.json";

    std::list<creds_fetcher::krb_ticket_info*> test_ticket_info =
        read_meta_data_json( metadata_file_path );

    std::string krb_files_dir = "/usr/share/credentials-fetcher/krbdir";
    std::string test_lease_id = "test1234567890";

    int result = write_meta_data_json( test_ticket_info, test_lease_id, krb_files_dir );

    if ( result != 0 )
    {
        std::cout << "write meta data to file test is failed" << std::endl;
        return EXIT_FAILURE;
    }

    // finally delete test lease directory
    boost::filesystem::remove_all( krb_files_dir + "/" + test_lease_id );

    std::cout << "write meta data info to file test is successful" << std::endl;
    return EXIT_SUCCESS;
}
