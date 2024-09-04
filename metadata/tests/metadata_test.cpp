#include "daemon.h"
#include <filesystem>
#include <fstream>

int read_meta_data_json_test()
{
    std::string metadata_file_path = "metadata_sample.json";

    std::vector<std::string> paths = {
        "/usr/share/credentials-fetcher/krbdir/73099acdb5807b4bbf91/ccname_WebApp01_7K4PEM",
        "/usr/share/credentials-fetcher/krbdir/73099acdb5807b4bbf91/ccname_WebApp03_53Yg4I" };

    for ( auto file_path : paths )
    {
        // create the meta file in the lease directory
        std::filesystem::path dirPath( file_path );
        std::filesystem::create_directories( dirPath.parent_path() );

        if ( !std::filesystem::exists( file_path ) )
        {
            std::ofstream file( file_path );
            file.close();
        }
    }

    std::list<krb_ticket_info_t*> result = read_meta_data_json( metadata_file_path );

    if ( result.empty() || result.size() != 2 )
    {
        std::cout << "reading meta data file test is failed" << std::endl;
        for ( auto file_path : paths )
        {
           std::filesystem::remove_all(file_path );
        }
        return EXIT_FAILURE;
    }

    std::cout << "read meta data file test is successful" << std::endl;
    for ( auto file_path : paths )
    {
        std::filesystem::remove_all(file_path );
    }
    return EXIT_SUCCESS;
}

int read_meta_data_invalid_json_test()
{
    std::string metadata_file_path = "metadata_invalid_sample.json";

    std::list<krb_ticket_info_t*> result = read_meta_data_json( metadata_file_path );

    if ( result.empty() )
    {
        std::cout << "\nread invalid metadata test is successful" << std::endl;
        return EXIT_SUCCESS;
    }
    std::cout << "\nread invalid metadata test is failed" << std::endl;
    return EXIT_FAILURE;
}

int write_meta_data_json_test()
{
    std::string metadata_file_path = "metadata_sample.json";

    std::vector<std::string> paths = {
        "/usr/share/credentials-fetcher/krbdir/73099acdb5807b4bbf91/ccname_WebApp01_7K4PEM",
        "/usr/share/credentials-fetcher/krbdir/73099acdb5807b4bbf91/ccname_WebApp03_53Yg4I" };

    for ( auto file_path : paths )
    {
        // create the meta file in the lease directory
        std::filesystem::path dirPath( file_path );
        std::filesystem::create_directories( dirPath.parent_path() );

        if ( !std::filesystem::exists( file_path ) )
        {
            std::ofstream file( file_path );
            file.close();
        }
    }

    std::list<krb_ticket_info_t *> test_ticket_info =
        read_meta_data_json( metadata_file_path );

    std::string krb_files_dir = "/usr/share/credentials-fetcher/krbdir";
    std::string test_lease_id = "test1234567890";

    int result = write_meta_data_json( test_ticket_info, test_lease_id, krb_files_dir );

    if ( result != 0 )
    {
        std::cout << "write meta data to file test is failed" << std::endl;
        for ( auto file_path : paths )
        {
            std::filesystem::remove_all(file_path );
        }
        return EXIT_FAILURE;
    }

    // finally delete test lease directory
    std::filesystem::remove_all( krb_files_dir + "/" + test_lease_id );

    std::cout << "write meta data info to file test is successful" << std::endl;
    for ( auto file_path : paths )
    {
        std::filesystem::remove_all(file_path );
    }
    return EXIT_SUCCESS;
}
