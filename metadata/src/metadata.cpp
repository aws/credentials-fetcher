#include "daemon.h"
#include <filesystem>
#include <fstream>
#include <vector>

static const std::vector<char> invalid_path_characters = {
    '&', ':', '\\', '|', '*', '?', '<', '>', '`', '$', '{', '}', '(', ')', '"', ';' };
/**
 *
 * @param path - string input that has to be validated
 * @return true or false if string contains or not contains invalid characters
 */
bool contains_invalid_characters( const std::string& path )
{
    bool result = false;
    // Iterate over all characters in invalid_path_characters vector
    for ( const char& ch : invalid_path_characters )
    {
        // Check if character exist in string
        if ( path.find( ch ) != std::string::npos )
        {
            result = true;
            break;
        }
    }
    return result;
}
/**
 * read the kerberos ticket information from the cache
 * @param file_path - file path for the metadata associated to a lease
 * @param krb_files_dir - path of the dir for kerberos tickets
 * @return vector of kerberos ticket info
 */
std::list<creds_fetcher::krb_ticket_info*> read_meta_data_json( std::string file_path )
{
    std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list;
    try
    {
        if ( file_path.empty() )
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: meta data file is empty"  <<
                std::endl;
            return krb_ticket_info_list;
        }

        // deserialize json to krb_ticket_info object
        Json::Value root;
        std::ifstream json_file( file_path );

        if ( json_file.is_open() )
        {
            json_file >> root;
            json_file.close();

            // deserialize json to krb_ticket_info object
            const Json::Value& child_tree_krb_info = root["krb_ticket_info"];

            for ( const Json::Value& krb_info : child_tree_krb_info )
            {
                creds_fetcher::krb_ticket_info* krb_ticket_info =
                    new creds_fetcher::krb_ticket_info;
                std::string krb_file_path = krb_info["krb_file_path"].asString();

                if ( contains_invalid_characters( krb_file_path ) )
                {
                    std::cout << getCurrentTime() << '\t' << "ERROR: krb file path contains invalid characters"  <<
                        std::endl;
                    free( krb_ticket_info );
                    break;
                }

                // only add path if it exists
                if ( std::filesystem::exists( krb_file_path ) )
                {
                    krb_ticket_info->krb_file_path = krb_file_path;
                    krb_ticket_info->service_account_name =
                        krb_info["service_account_name"].asString();
                    krb_ticket_info->domain_name = krb_info["domain_name"].asString();
                    krb_ticket_info->domainless_user = krb_info["domainless_user"].asString();

                    krb_ticket_info_list.push_back( krb_ticket_info );
                }
            }
        }
    }
    catch ( const std::exception& ex )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: '" << ex.what() << "'!" << std::endl;
        std::cout << getCurrentTime() << '\t' << "ERROR: meta data file is not properly formatted"  <<
            std::endl;
        return krb_ticket_info_list;
    }

    return krb_ticket_info_list;
}

/**
 * write the kerberos ticket information to the cache
 * Example meta_file:
 * {
    "krb_ticket_info": [
        {
            "krb_file_path":
"\/usr\/share\/credentials-fetcher\/krbdir\/3e1ff0bb9f966192c440\/ccname_WebApp01_OPMsbZ",
            "service_account_name": "WebApp01",
            "domain_name": "contoso.com",
            "domainless_user": "user1"
        }
    ]
}

 * @param krb_ticket_info - info of the kerberos ticket to create
 * @param lease_id - lease_id associated to the kerberos ticket created
 * @param krb_files_dir - path of the dir for kerberos ticket
 * @return 0 or 1 for successful or failed writes
 */

int write_meta_data_json( creds_fetcher::krb_ticket_info* krb_ticket_info,
                          std::string lease_id, std::string krb_files_dir )
{
    std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list;

    krb_ticket_info_list.push_back(krb_ticket_info);
    
    return write_meta_data_json(krb_ticket_info_list, lease_id, krb_files_dir);
}

/* @param krb_ticket_info_list - info of the kerberos tickets created
 * @param lease_id - lease_id associated to the kerberos tickets created
 * @param krb_files_dir - path of the dir for kerberos tickets
 * @return 0 or 1 for successful or failed writes
 */
int write_meta_data_json( std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list,
                          std::string lease_id, std::string krb_files_dir )
{
    try
    {
        std::string meta_file_name = lease_id + "_metadata.json";
        std::string file_path = krb_files_dir + "/" + lease_id + "/" + meta_file_name;

        // create the meta file in the lease directory
        std::filesystem::path dirPath( file_path );
        std::filesystem::create_directories( dirPath.parent_path() );

        // parse the kerberos info and serialize to json
        Json::Value root;
        Json::Value krb_ticket_info_parent;

        for ( auto krb_ticket_info : krb_ticket_info_list )
        {
            Json::Value ticket_info;
            ticket_info["krb_file_path"] = krb_ticket_info->krb_file_path;
            ticket_info["service_account_name"] = krb_ticket_info->service_account_name;
            ticket_info["domain_name"] = krb_ticket_info->domain_name;
            ticket_info["domainless_user"] = krb_ticket_info->domainless_user;

            krb_ticket_info_parent.append( ticket_info );
        }

        root["krb_ticket_info"] = krb_ticket_info_parent;

        Json::StreamWriterBuilder writer;
        std::string jsonString = Json::writeString( writer, root );
        std::ofstream json_file( file_path );
        if ( json_file.is_open() )
        {
            json_file << jsonString;
            json_file.close();
        }
        else
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: Failed to write JSON file: " << file_path << std::endl;
        }
    }
    catch ( const std::exception& ex )
    {
        std::cout << getCurrentTime() << '\t' << "ERROR: '" << ex.what() << "'!" << std::endl;
        std::cout << getCurrentTime() << '\t' << "ERROR: failed to write meta data file"  <<
            std::endl;
        return -1;
    }
    return 0;
}
