#include "daemon.h"
#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <fstream>
#include <vector>

static const std::vector<char> invalid_path_characters = {
    '&', ':', '\\', '|', '*', '?', '<', '>', '`', '$', '{', '}', '(', ')', '"' ,';'};
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
            fprintf( stderr, SD_CRIT "meta data file is empty" );
            return krb_ticket_info_list;
        }

        // deserialize json to krb_ticket_info object
        namespace pt = boost::property_tree;
        pt::ptree root;
        pt::read_json( file_path, root );

        const pt::ptree& child_tree_krb_info = root.get_child( "krb_ticket_info" );

        for ( const auto& kv : child_tree_krb_info )
        {
            creds_fetcher::krb_ticket_info* krb_ticket_info = new creds_fetcher::krb_ticket_info;
            std::string krb_file_path = kv.second.get<std::string>( "krb_file_path" );

            if ( contains_invalid_characters( krb_file_path ) )
            {
                fprintf( stderr, SD_CRIT "krb file path contains invalid characters" );
                free( krb_ticket_info );
                break;
            }

            // only add path if it exists
            if ( boost::filesystem::exists( krb_file_path ) )
            {
                krb_ticket_info->krb_file_path = krb_file_path;
                krb_ticket_info->service_account_name =
                    kv.second.get<std::string>( "service_account_name" );
                krb_ticket_info->domain_name = kv.second.get<std::string>( "domain_name" );

                krb_ticket_info_list.push_back( krb_ticket_info );
            }
        }
    }
    catch ( const std::exception& ex )
    {
        std::cout << "Exception: '" << ex.what() << "'!" << std::endl;
        fprintf( stderr, SD_CRIT "meta data file is not properly formatted" );
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
            "domain_name": "contoso.com"
        }
    ]
}
 * @param krb_ticket_info_list - info of the kerberos tickets created
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
        boost::filesystem::path dirPath( file_path );
        boost::filesystem::create_directories( dirPath.parent_path() );

        // parse the kerberos info and serialize to json
        boost::property_tree::ptree root;
        boost::property_tree::ptree krb_ticket_info_parent;

        for ( auto krb_ticket_info : krb_ticket_info_list )
        {
            boost::property_tree::ptree ticket_info;
            ticket_info.put( "krb_file_path", krb_ticket_info->krb_file_path );
            ticket_info.put( "service_account_name", krb_ticket_info->service_account_name );
            ticket_info.put( "domain_name", krb_ticket_info->domain_name );

            krb_ticket_info_parent.push_back( std::make_pair( "", ticket_info ) );
        }

        root.add_child( "krb_ticket_info", krb_ticket_info_parent );
        boost::property_tree::write_json( file_path, root );
    }
    catch ( const std::exception& ex )
    {
        std::cout << "Exception: '" << ex.what() << "'!" << std::endl;
        fprintf( stderr, SD_CRIT "failed to write meta data file" );
        return -1;
    }
    return 0;
}
