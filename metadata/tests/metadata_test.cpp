#include "daemon.h"
#include <filesystem>
#include <fstream>

int read_meta_data_json_test()
{
    std::string metadata_file_path = "/usr/sbin/credentials_fetcher_metadata_sample.json";
    std::string metadata_alt_file_path = "metadata_sample.json";
    std::string krb_files_dir = std::string("/tmp/") + CF_KRB_DIR + std::string("/");
    std::string logging_dir = std::string("/tmp/") + CF_LOGGING_DIR + std::string("/");

    std::string cmd = "mkdir -p " + krb_files_dir + " " + logging_dir;
    FILE* pFile = popen( cmd.c_str(), "r" );
    if ( pFile == nullptr )
    {
        return EXIT_FAILURE;
    }

    std::vector<std::string> paths = {
        krb_files_dir + std::string("73099acdb5807b4bbf91/ccname_WebApp01_7K4PEM"),
        krb_files_dir + std::string("73099acdb5807b4bbf91/ccname_WebApp03_53Yg4I") };

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

    std::list<creds_fetcher::krb_ticket_info*> result
	    = read_meta_data_json( metadata_file_path, metadata_alt_file_path,
			    krb_files_dir + std::string("73099acdb5807b4bbf91/ccname_WebApp01_7K4PEM") );

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

    std::list<creds_fetcher::krb_ticket_info*> result = read_meta_data_json( metadata_file_path );

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
    std::string krb_files_dir = std::string("/tmp/") + CF_KRB_DIR + std::string("/");
    std::string logging_dir = std::string("/tmp/") + CF_LOGGING_DIR + std::string("/");

    std::vector<std::string> paths = {
        "73099acdb5807b4bbf91/ccname_WebApp01_7K4PEM",
        "73099acdb5807b4bbf91/ccname_WebApp03_53Yg4I" };

    for ( auto file_path : paths )
    {
        // create the meta file in the lease directory
        std::filesystem::path dirPath( krb_files_dir + file_path );
        std::filesystem::create_directories( dirPath.parent_path() );

        if ( !std::filesystem::exists( file_path ) )
        {
            std::ofstream file( file_path );
            file.close();
        }
    }

    std::list<creds_fetcher::krb_ticket_info*> test_ticket_info =
        read_meta_data_json( metadata_file_path );

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
