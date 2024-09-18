#include "constants.h"
#include "daemon.h"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <openssl/crypto.h>
#include <string>
#include <sys/stat.h>
#include <utility>

extern const std::vector<char> invalid_characters;
extern const std::string install_path_for_decode_exe;
extern const std::string install_path_for_aws_cli;

class Util
{
  public:
    /**
     * Check if binary is writable other than root
     * @param filename - must be owned and writable only by root
     * @return - true or false
     */
    static bool check_file_permissions( std::string filename )
    {
        struct stat st;

        if ( lstat( filename.c_str(), &st ) == -1 )
        {
            return false;
        }

        // S_IWOTH - Write permission bit for other users. Usually 02.
        if ( ( st.st_uid != 0 ) || ( st.st_gid != 0 ) || ( st.st_mode & S_IWOTH ) )
        {
            return false;
        }

        return true;
    }

    static std::pair<int, std::string> check_util_binaries_permissions()
    {
        std::pair<int, std::string> result;

        std::pair<int, std::string> cmd = Util::exec_shell_cmd( "which kinit" );
        Util::rtrim( cmd.second );
        if ( !Util::check_file_permissions( cmd.second ) )
        {
            std::cerr << Util::getCurrentTime() << '\t' << "ERROR: kinit not found" << std::endl;
            result = std::make_pair( -1, std::string( "ERROR:: kinit not found" ) );
            return result;
        }

        cmd = Util::exec_shell_cmd( "which ldapsearch" );
        Util::rtrim( cmd.second );
        if ( !Util::check_file_permissions( cmd.second ) )
        {
            std::cerr << Util::getCurrentTime() << '\t' << "ERROR: ldapsearch not found"
                      << std::endl;
            result = std::make_pair( -1, "ERROR:: ldapsearch not found" );
            return result;
        }

        if ( !Util::check_file_permissions( std::string( install_path_for_decode_exe ) ) )
        {
            result = std::make_pair( -1, "ERROR:: decode.exe not found" );
            return result;
        }

        if ( !Util::check_file_permissions( std::string( install_path_for_aws_cli ) ) )
        {
            result = std::make_pair( -1, "ERROR:: AWS CLI not found" );
            return result;
        }
        return std::make_pair( 0, "" );
    }

    /**
     * Execute a shell command such as "ls /tmp/"
     * output is a pair of error code and output log
     * @param cmd - command to be executed in shell
     * @return result pair(error-code, output log of shell execution)
     */
    static std::pair<int, std::string> exec_shell_cmd( std::string cmd )
    {
        std::string output;
        char line[80];

        char* cmd_str = (char*)calloc( cmd.length() + 1, sizeof( char ) );
        strncpy( cmd_str, cmd.c_str(), cmd.length() );

        FILE* pFile = popen( cmd_str, "r" );
        if ( pFile == nullptr )
        {
            std::pair<int, std::string> result = std::make_pair( -1, std::string( "" ) );
            free( cmd_str );
            return result;
        }

        while ( fgets( line, sizeof( line ), pFile ) != nullptr )
        {
            output += std::string( line );
        }

        int error_code = pclose( pFile );

        std::pair<int, std::string> result = std::make_pair( error_code, output );
        free( cmd_str );

        return result;
    }

    static std::pair<int, std::string> get_realm_name()
    {
        std::pair<int, std::string> result;

        std::pair<int, std::string> realm_name_result = exec_shell_cmd(
            "realm list | grep  'realm-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
        if ( realm_name_result.first != 0 )
        {
            result.first = realm_name_result.first;
            realm_name_result = exec_shell_cmd(
                "net ads info | grep  'Realm' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
            if ( realm_name_result.first != 0 )
            {
                result.first = realm_name_result.first;
                return result;
            }
        }

        return realm_name_result;
    }

    static std::pair<int, std::string> check_domain_name( std::string domain_name )
    {
        std::pair<int, std::string> domain_name_result = exec_shell_cmd(
            "realm list | grep  'domain-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
        if ( domain_name_result.first != 0 ||
             ( not std::equal( domain_name_result.second.begin(), domain_name_result.second.end(),
                               domain_name.begin() ) ) )
        {
            domain_name_result.first = -1;
            return domain_name_result;
        }

        return domain_name_result;
    }

    static std::pair<int, std::string> is_hostname_cmd_present()
    {
        std::pair<int, std::string> cmd = exec_shell_cmd( "which hostname" );
        rtrim( cmd.second );
        if ( !check_file_permissions( cmd.second ) )
        {
            std::pair<int, std::string> result =
                std::make_pair( -1, std::string( "ERROR: hostname not found" ) );
            return result;
        }

        return cmd;
    }

    static std::pair<int, std::string> is_realm_cmd_present()
    {
        std::pair<int, std::string> cmd = exec_shell_cmd( "which realm" );
        rtrim( cmd.second );
        if ( !check_file_permissions( cmd.second ) )
        {
            std::cerr << getCurrentTime() << '\t' << "ERROR: realm not found" << std::endl;
            std::pair<int, std::string> result =
                std::make_pair( -1, std::string( "ERROR: realm not found" ) );
            return result;
        }

        return cmd;
    }

    static std::pair<int, std::string> is_kinit_cmd_present()
    {
        std::pair<int, std::string> cmd = exec_shell_cmd( "which kinit" );
        rtrim( cmd.second );
        if ( !check_file_permissions( cmd.second ) )
        {
            std::cerr << getCurrentTime() << '\t' << "ERROR: kinit not found" << std::endl;
            std::pair<int, std::string> result =
                std::make_pair( -1, std::string( "ERROR: kinit not found" ) );
            return result;
        }

        return cmd;
    }

    static std::pair<int, std::string> is_ldapsearch_cmd_present()
    {
        std::pair<int, std::string> cmd = exec_shell_cmd( "which ldapsearch" );
        rtrim( cmd.second );
        if ( !check_file_permissions( cmd.second ) )
        {
            std::cerr << getCurrentTime() << '\t' << "ERROR: ldapsearch not found" << std::endl;
            std::pair<int, std::string> result =
                std::make_pair( -1, std::string( "ERROR: ldapsearch not found" ) );
            return result;
        }

        return cmd;
    }

    static std::pair<int, std::string> is_decode_exe_present()
    {
        std::pair<int, std::string> result;

        if ( !check_file_permissions( install_path_for_decode_exe ) )
        {
            std::pair<int, std::string> result =
                std::make_pair( -1, std::string( "ERROR: decode.exe not found" ) );
            return result;
        }

        result = std::make_pair( 0, "" );

        return result;
    }

    static std::string retrieve_variable_from_ecs_config( std::string ecs_variable_name )
    {
        const char* ecs_config_file_name = "/etc/ecs/ecs.config";

        std::ifstream config_file( ecs_config_file_name );
        std::string line;
        std::vector<std::string> results;

        while ( std::getline( config_file, line ) )
        {
            results = Util::split_string( line, '=' );

            if ( results.empty() || results.size() != 2 )
            {
                std::cerr << Util::getCurrentTime() << '\t' << "invalid configuration format"
                          << std::endl;
                return "";
            }

            std::string key = results[0];
            std::string value = results[1];

            Util::rtrim( key );
            Util::ltrim( value );

            if ( key.compare( ENV_CF_GMSA_BASE_DN ) == 0 && ecs_variable_name.compare( key ) == 0 )
            {
                return value;
            }

            if ( key.compare( ENV_CF_GMSA_SECRET_NAME ) == 0 &&
                 ecs_variable_name.compare( key ) == 0 )
            {
                return value;
            }

            if ( key.compare( ENV_CF_DOMAIN_CONTROLLER ) == 0 &&
                 ecs_variable_name.compare( key ) == 0 )
            {
                return value;
            }
        }

        return "";
    }

    static Json::Value get_secret_from_secrets_manager( std::string aws_sm_secret_name )
    {
        Json::Value root = Json::nullValue;

        std::string command = std::string( install_path_for_aws_cli ) +
                              std::string( " secretsmanager get-secret-value --secret-id " ) +
                              aws_sm_secret_name + " --query 'SecretString' --output text";
        // /usr/bin/aws secretsmanager get-secret-value --secret-id
        // aws/directoryservices/d-xxxxxxxxxx/gmsa --query 'SecretString' --output text
        std::pair<int, std::string> result = Util::exec_shell_cmd( command );

        if ( result.first == 0 )
        {
            // deserialize json to krb_ticket_info object
            Json::CharReaderBuilder reader;
            std::istringstream string_stream( result.second );
            std::string errors;
            Json::parseFromStream( reader, string_stream, &root, &errors );
        }

        return root;
    }

    static std::pair<int, std::string> get_base_dn_from_secret()
    {
        std::pair<int, std::string> result = std::make_pair( -1, "" );
        std::string distinguished_name;
        std::string secret_name = retrieve_variable_from_ecs_config( ENV_CF_GMSA_SECRET_NAME );
        if ( !secret_name.empty() )
        {
            Json::Value root = get_secret_from_secrets_manager( secret_name );
            distinguished_name = root["distinguishedName"].asString();
            if ( !distinguished_name.empty() )
            {
                result.first = 0;
            }
            result.second = distinguished_name;
        }

        return result;
    }

    static std::vector<std::string> get_FQDN_list( std::string domain_name )
    {
        std::string domain_controller_gmsa( ENV_CF_DOMAIN_CONTROLLER );

        std::string fqdn_from_env_var;
        fqdn_from_env_var = Util::retrieve_variable_from_ecs_config( domain_controller_gmsa );

        std::vector<std::string> fqdn_list;
        if ( fqdn_from_env_var.empty() )
        {
            fqdn_list = Util::get_FQDNs( domain_name );
            for ( auto fqdn : fqdn_list )
            {
                std::cerr << "Found ldap._tcp.dc._msdcs DNS controller " << fqdn << std::endl;
            }
        }
        else
        {
            fqdn_list.push_back( fqdn_from_env_var );
        }

        return fqdn_list;
    }

    /**
     * UTF-16 diagnostic: Test utf16 capability
     * @return - true (pass) or false (fail)
     */
    static int test_utf16_decode()
    {
        const char* test_msds_managed_password =
            "msDS-ManagedPassword:: "
            "AQAAACIBAAAQAAAAEgEaAciMhCofvo1R4kkVYm79aRysUcOs7NhhHvO"
            "exhNTV9KXAn1v8AYMN1lMC/V6W0dZVrQRpGZ/EvWi33Lq2xoR5ANuJf623JQRj3pMZQBqQLRjRoPn"
            "UJYY8H74aVysf0t+1M0moLkm0IPSCB52Mm0CC9flTT0D9KZV2Mvf4FpgvYpYoOQvUmd0UOV72Tk/d"
            "leM8zTWjRL5ccfzwt5p8akMEl6W0RPj1pDbqxtbpJFQiLQd7HRlSkYPeBKDB9r6CItrQTo8j+pgJf"
            "B4+wVbOUZuMXrKkDVh8XUOUBdGhznntRWnDM2DhwBoFEisBr133Vo8aRcedYqwNj/LEsrimEJaeuY"
            "AAAQCCBrPFgAABKQ3Z84WAAA= #";

        uint8_t test_password_buf[1024];

        const uint8_t test_gmsa_utf8_password[] = {
            0xE8, 0xB3, 0x88, 0xE2, 0xAA, 0x84, 0xEB, 0xB8, 0x9F, 0xE5, 0x86, 0x8D, 0xE4, 0xA7,
            0xA2, 0xE6, 0x88, 0x95, 0xEF, 0xB5, 0xAE, 0xE1, 0xB1, 0xA9, 0xE5, 0x86, 0xAC, 0xEA,
            0xB3, 0x83, 0xEF, 0xBF, 0xBD, 0xE1, 0xB9, 0xA1, 0xE9, 0xBB, 0xB3, 0xE1, 0x8F, 0x86,
            0xE5, 0x9D, 0x93, 0xE9, 0x9F, 0x92, 0xE7, 0xB4, 0x82, 0xEF, 0x81, 0xAF, 0xE0, 0xB0,
            0x86, 0xE5, 0xA4, 0xB7, 0xE0, 0xAD, 0x8C, 0xE7, 0xAB, 0xB5, 0xE4, 0x9D, 0x9B, 0xE5,
            0x99, 0x99, 0xE1, 0x86, 0xB4, 0xE6, 0x9A, 0xA4, 0xE1, 0x89, 0xBF, 0xEA, 0x8B, 0xB5,
            0xE7, 0x8B, 0x9F, 0xEF, 0xBF, 0xBD, 0xE1, 0x84, 0x9A, 0xCF, 0xA4, 0xE2, 0x95, 0xAE,
            0xEB, 0x9B, 0xBE, 0xE9, 0x93, 0x9C, 0xE8, 0xBC, 0x91, 0xE4, 0xB1, 0xBA, 0x65, 0xE4,
            0x81, 0xAA, 0xE6, 0x8E, 0xB4, 0xE8, 0x8D, 0x86, 0xE5, 0x83, 0xA7, 0xE1, 0xA2, 0x96,
            0xE7, 0xBB, 0xB0, 0xE6, 0xA7, 0xB8, 0xEA, 0xB1, 0x9C, 0xE4, 0xAD, 0xBF, 0xED, 0x91,
            0xBE, 0xE2, 0x9B, 0x8D, 0xEB, 0xA6, 0xA0, 0xED, 0x80, 0xA6, 0xED, 0x8A, 0x83, 0xE1,
            0xB8, 0x88, 0xE3, 0x89, 0xB6, 0xC9, 0xAD, 0xED, 0x9C, 0x8B, 0xE4, 0xB7, 0xA5, 0xCC,
            0xBD, 0xEA, 0x9B, 0xB4, 0xF0, 0xA5, 0x9F, 0x8B, 0xE5, 0xAB, 0xA0, 0xEB, 0xB5, 0xA0,
            0xE5, 0xA2, 0x8A, 0xEE, 0x92, 0xA0, 0xE5, 0x88, 0xAF, 0xE7, 0x91, 0xA7, 0xEE, 0x95,
            0x90, 0xEF, 0xBF, 0xBD, 0xE3, 0xBC, 0xB9, 0xE5, 0x9D, 0xB6, 0xEF, 0x8E, 0x8C, 0xED,
            0x98, 0xB4, 0xE1, 0x8A, 0x8D, 0xE7, 0x87, 0xB9, 0xEF, 0x8F, 0x87, 0xEF, 0xBF, 0xBD,
            0xEF, 0x85, 0xA9, 0xE0, 0xB2, 0xA9, 0xE5, 0xB8, 0x92, 0xED, 0x86, 0x96, 0xEE, 0x8C,
            0x93, 0xE9, 0x83, 0x96, 0xEA, 0xAF, 0x9B, 0xE5, 0xAC, 0x9B, 0xE9, 0x86, 0xA4, 0xE8,
            0xA1, 0x90, 0xE1, 0xB6, 0xB4, 0xE7, 0x93, 0xAC, 0xE4, 0xA9, 0xA5, 0xE0, 0xBD, 0x86,
            0xE1, 0x89, 0xB8, 0xDE, 0x83, 0xEF, 0xAB, 0x9A, 0xE8, 0xAC, 0x88, 0xE4, 0x85, 0xAB,
            0xE3, 0xB0, 0xBA, 0xEE, 0xAA, 0x8F, 0xE2, 0x95, 0xA0, 0xE7, 0xA3, 0xB0, 0xD7, 0xBB,
            0xE3, 0xA5, 0x9B, 0xE6, 0xB9, 0x86, 0xE7, 0xA8, 0xB1, 0xE9, 0x83, 0x8A, 0xE6, 0x84,
            0xB5, 0xE7, 0x97, 0xB1, 0xE5, 0x80, 0x8E, 0xE4, 0x98, 0x97, 0xE3, 0xA6, 0x87, 0xEB,
            0x97, 0xA7, 0xEA, 0x9C, 0x95, 0xEC, 0xB4, 0x8C, 0xE8, 0x9E, 0x83, 0xE6, 0xA0, 0x80,
            0xE4, 0xA0, 0x94, 0xDA, 0xAC, 0xE7, 0x9E, 0xBD, 0xE5, 0xAB, 0x9D, 0xE6, 0xA4, 0xBC,
            0xE1, 0xB8, 0x97, 0xE8, 0xA9, 0xB5, 0xE3, 0x9A, 0xB0, 0xEC, 0xAC, 0xBF, 0xEC, 0xA8,
            0x92, 0xE9, 0xA3, 0xA2, 0xE5, 0xA9, 0x82, 0xEE, 0x99, 0xBA };

        std::string decoded_password_file = "./decoded_password_file";

        std::pair<size_t, void*> base64_decoded_password_blob =
            find_password( test_msds_managed_password );
        if ( base64_decoded_password_blob.first == 0 ||
             base64_decoded_password_blob.second == nullptr )
        {
            return EXIT_FAILURE;
        }

        struct stat st;
        std::string decode_exe_path;

        if ( stat( install_path_for_decode_exe.c_str(), &st ) == 0 )
        {
            decode_exe_path = install_path_for_decode_exe;
        }
        else
        {
            // For test during rpmbuild
            decode_exe_path = "./decode.exe";
        }

        // Use decode.exe in build directory
        std::string decode_cmd = decode_exe_path + std::string( "  > " ) + decoded_password_file;
        blob_t* blob = ( (blob_t*)base64_decoded_password_blob.second );
        FILE* fp = popen( decode_cmd.c_str(), "w" );
        if ( fp == nullptr )
        {
            std::cerr << Util::getCurrentTime() << '\t' << "Self test failed" << std::endl;
            OPENSSL_cleanse( base64_decoded_password_blob.second,
                             base64_decoded_password_blob.first );
            OPENSSL_free( base64_decoded_password_blob.second );
            return EXIT_FAILURE;
        }
        fwrite( blob->current_password, 1, GMSA_PASSWORD_SIZE, fp );
        if ( pclose( fp ) < 0 )
        {
            std::cerr << Util::getCurrentTime() << '\t' << "Self test failed" << std::endl;
            OPENSSL_cleanse( base64_decoded_password_blob.second,
                             base64_decoded_password_blob.first );
            OPENSSL_free( base64_decoded_password_blob.second );
            return EXIT_FAILURE;
        }

        fp = fopen( decoded_password_file.c_str(), "rb" );
        if ( fp == nullptr )
        {
            std::cerr << Util::getCurrentTime() << '\t' << "Self test failed" << std::endl;
            OPENSSL_cleanse( base64_decoded_password_blob.second,
                             base64_decoded_password_blob.first );
            OPENSSL_free( base64_decoded_password_blob.second );
            return EXIT_FAILURE;
        }
        fread( test_password_buf, 1, GMSA_PASSWORD_SIZE, fp );

        if ( memcmp( test_gmsa_utf8_password, test_password_buf, GMSA_PASSWORD_SIZE ) == 0 )
        {
            // utf16->utf8 conversion works as expected
            std::cerr << Util::getCurrentTime() << '\t' << "Self test is successful" << std::endl;
            OPENSSL_cleanse( base64_decoded_password_blob.second,
                             base64_decoded_password_blob.first );
            OPENSSL_free( base64_decoded_password_blob.second );
            unlink( decoded_password_file.c_str() );
            return EXIT_SUCCESS;
        }

        std::cerr << Util::getCurrentTime() << '\t' << "Self test failed" << std::endl;
        OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
        OPENSSL_free( base64_decoded_password_blob.second );
        unlink( decoded_password_file.c_str() );
        return EXIT_FAILURE;
    }

    /**
     * base64_decode - Decodes base64 encoded string
     * @param password - base64 encoded password
     * @param base64_decode_len - Length after decode
     * @return buffer with base64 decoded contents
     */
    static uint8_t* base64_decode( const std::string& password, gsize* base64_decode_len )
    {
        if ( base64_decode_len == nullptr || password.empty() )
        {
            return nullptr;
        }

        *base64_decode_len = 0;
        guchar* result = g_base64_decode( password.c_str(), base64_decode_len );
        if ( result == nullptr || *base64_decode_len <= 0 )
        {
            return nullptr;
        }

        void* secure_mem = OPENSSL_malloc( *base64_decode_len );
        if ( secure_mem == nullptr )
        {
            g_free( result );
            return nullptr;
        }

        memcpy( secure_mem, result, *base64_decode_len );

        memset( result, 0, *base64_decode_len );
        g_free( result );

        /**
         * secure_mem must be freed later
         */
        return (uint8_t*)secure_mem;
    }

    static std::pair<size_t, void*> find_password( std::string ldap_search_result )
    {
        size_t base64_decode_len = 0;
        std::vector<std::string> results;

        std::string password = std::string( "msDS-ManagedPassword::" );
        results = Util::split_string( ldap_search_result, '#' );
        bool password_found = false;
        for ( auto& result : results )
        {
            auto found = result.find( password );
            if ( found != std::string::npos )
            {
                found += password.length();
                password = result.substr( found + 1, result.length() );
                // std::cerr << "Password = " << password << std::endl;
                password_found = true;
                break;
            }
        }

        uint8_t* blob_base64_decoded = nullptr;
        if ( password_found )
        {
            blob_base64_decoded = base64_decode( password, &base64_decode_len );
            if ( blob_base64_decoded == nullptr )
            {
                std::cerr << Util::getCurrentTime() << '\t' << "ERROR: base64 buffer is null"
                          << std::endl;
                return std::make_pair( 0, nullptr );
            }
        }

        return std::make_pair( base64_decode_len, blob_base64_decoded );
    }

    static std::pair<int, std::string> execute_ldapsearch( std::string gmsa_account_name,
                                                           std::string env_base_dn,
                                                           std::string default_base_dn,
                                                           std::string gmsa_ou, std::string fqdn )
    {
        std::string cmd;
        std::pair<int, std::string> ldap_search_result;

        if ( !env_base_dn.empty() )
        {
            cmd = std::string( "ldapsearch -LLL -Y GSSAPI -H ldap://" ) + fqdn;
            cmd += std::string( " -b " ) + env_base_dn + std::string( " msds-ManagedPassword" );
        }
        else
        {
            cmd = std::string( "ldapsearch -H ldap://" ) + fqdn;
            cmd += std::string( " -b 'CN=" ) + gmsa_account_name + gmsa_ou + default_base_dn +
                   std::string( "'" ) +
                   std::string( " -s sub  '(objectClass=msDs-GroupManagedServiceAccount)' "
                                " msDS-ManagedPassword" );
        }

        std::cerr << Util::getCurrentTime() << '\t' << "INFO: " << cmd << std::endl;
        std::cerr << cmd << std::endl;

        for ( int i = 0; i < 2; i++ )
        {
            ldap_search_result = Util::exec_shell_cmd( cmd );
            cmd += ldap_search_result.second;
            ldap_search_result.second = cmd;
            // Add retry, ldapsearch seems to fail and then succeed on retry
            if ( ldap_search_result.first != 0 )
            {
                std::string err_msg = std::string( "ERROR: ldapsearch failed with FQDN = " ) + fqdn;
                std::cerr << err_msg << std::endl;
                err_msg = Util::getCurrentTime() +
                          std::string( "ERROR: ldapsearch failed to get gMSA credentials: " +
                                       ldap_search_result.second );
                std::cerr << err_msg << std::endl;
                err_msg = ldap_search_result.second + err_msg;
                ldap_search_result.second = err_msg;
            }
            else
            {
                std::string err_msg = "INFO: ldapsearch succeeded with FQDN = ";
                std::cerr << err_msg << fqdn << std::endl;
                ldap_search_result.first = 0;
                ldap_search_result.second = ldap_search_result.second + err_msg;
                break;
            }
        }

        return ldap_search_result;
    }

    // Remove trailing characters in FQDN returned by dig command
    static std::string remove_trailing_dot_and_newline( std::string arg )
    {
        if ( arg.back() == '\n' || arg.back() == '\r' )
        {
            arg.pop_back();
        }
        if ( arg.back() == '.' )
        {
            arg.pop_back();
        }

        return arg;
    }

    static std::vector<std::string> get_FQDNs( std::string domain_name )
    {
        /**
         * Find SRV record
         *  "The SRV or "service locator" DNS record type enables service discovery in the DNS.
         *   SRV records allow services to be advertised on specific ports and used in an order
         * controlled by the owner of the service. SRV also provides a load balancing feature."
         *  https://www.nslookup.io/learning/dns-record-types/srv/
         */

        // https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/verify-srv-dns-records-have-been-created#method-3-use-nslookup
        std::string cmd = "nslookup -type=srv _ldap._tcp.dc._msdcs." + domain_name + " | grep " +
                          domain_name + " | sed 's/^.* //g'";

        std::pair<int, std::string> nslookup_output = Util::exec_shell_cmd( cmd );
        std::vector<std::string> fqdns;

        if ( nslookup_output.first == 0 )
        {
            fqdns = split_string( nslookup_output.second, '\n' );
            for ( auto& fqdn : fqdns )
            {
                if ( fqdn.back() == '.' )
                {
                    fqdn.pop_back();
                }
            }

            return fqdns;
        }
        else
        {
            cmd = "dig +short _ldap._tcp.dc._msdcs." + domain_name + " -t any | sed 's/^.* //g'";
            nslookup_output = Util::exec_shell_cmd( cmd );
            if ( nslookup_output.first == 0 )
            {
                std::vector<std::string> fqdns = split_string( nslookup_output.second, '\n' );
                for ( auto& fqdn : fqdns )
                {
                    if ( fqdn.back() == '.' )
                    {
                        fqdn.pop_back();
                    }
                }
                return fqdns;
            }
        }

        return fqdns;
    }

    static std::pair<int, std::string> execute_kinit_in_domain_joined_case( std::string principal )
    {
        // kinit -k 'EC2AMAZ-8L8GWS$@CONTOSO.COM'
        std::transform( principal.begin(), principal.end(), principal.begin(),
                        []( unsigned char c ) { return std::toupper( c ); } );
        std::string kinit_cmd = "kinit -kt /etc/krb5.keytab " + principal;
        std::pair<int, std::string> result = exec_shell_cmd( kinit_cmd );
        return result;
    }

    /**
     * Given an input string split based on provided delimiter and return the split strings as
     * vector
     *
     * @param input_string - input string to split
     * @param delimiter - char to split the input string on
     * @return results - results to store vector of strings after `input_string` is split
     */
    static std::vector<std::string> split_string( std::string input_string, char delimiter )
    {
        std::vector<std::string> results;
        std::istringstream input_string_stream( input_string );
        std::string token;
        while ( std::getline( input_string_stream, token, delimiter ) )
        {
            results.push_back( token );
            if ( delimiter == '=' )
            {
                while ( std::getline( input_string_stream, token ) )
                {
                    results.push_back( token );
                }
                break;
            }
        }
        return results;
    }

    /**
     * trim from start (in place)
     * @param s - string input
     */
    static void ltrim( std::string& s )
    {
        s.erase( s.begin(), std::find_if( s.begin(), s.end(), []( unsigned char ch ) {
                     return !std::isspace( ch );
                 } ) );
    }

    /**
     * trim from end (in place)
     * @param s - string input
     */
    static void rtrim( std::string& s )
    {
        s.erase( std::find_if( s.rbegin(), s.rend(),
                               []( unsigned char ch ) { return !std::isspace( ch ); } )
                     .base(),
                 s.end() );
    }

    /**
     * get current time
     */
    static std::string getCurrentTime()
    {
        time_t now = time( 0 );
        struct tm tstruct;
        char buf[80];
        tstruct = *localtime( &now );
        strftime( buf, sizeof( buf ), "%Y-%m-%d %X", &tstruct );

        std::string curr_time = std::string( buf );
        return curr_time;
    }

    /** clear string **/
    static void clearString( std::string& str )
    {
        if ( !str.empty() )
        {
            // Use OPENSSL_cleanse to securely clear the memory
            OPENSSL_cleanse( &str[0], str.size() );
        }
        // Clear the string content
        str.clear();
    }

    /**
     * This function generates kerberos ticket with user credentials
     * User credentials must have adequate privileges to read gMSA passwords
     * This is an alternative to the machine credentials approach above
     * @param cf_daemon - parent daemon object
     * @return error-code - 0 if successful
     */
    static std::pair<int, std::string> generate_krb_ticket_using_secret_vault(
        std::string domain_name, std::string aws_sm_secret_name, CF_logger& cf_logger )
    {
        std::pair<int, std::string> result;

        result = Util::check_util_binaries_permissions();

        if ( result.first != 0 )
        {
            return result;
        }

        std::string username = "";
        std::string password = "";
        Json::Value root = Util::get_secret_from_secrets_manager( aws_sm_secret_name );

        std::string distinguished_name = "";
        if ( root != Json::nullValue )
        {
            // Read other
            distinguished_name = root["distinguishedName"].asString();
            username = root["username"].asString();
            password = root["password"].asString();
        }
        else
        {
            return std::make_pair( -1, "ERROR: username and password not found in secret" );
        }

        if ( !distinguished_name.empty() )
        {
            std::cerr << "[Optional] DN from Secrets Manager = " << distinguished_name << std::endl;
        }

        std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                        []( unsigned char c ) { return std::toupper( c ); } );

        // kinit using api interface
        char* kinit_argv[3];

        kinit_argv[0] = (char*)"my_kinit";
        username = username + "@" + domain_name;
        kinit_argv[1] = (char*)username.c_str();
        kinit_argv[2] = (char*)password.c_str();
        int ret = my_kinit_main( 2, kinit_argv );
#if 0
    /* The old way */
    std::string kinit_cmd = "echo '"  + password +  "' | kinit -V " + username + "@" +
                            domain_name;
    username = "xxxx";
    password = "xxxx";
    result = Util::exec_shell_cmd( kinit_cmd );
    kinit_cmd = "xxxx";
    return result.first;
#endif

        Util::clearString( username );
        Util::clearString( password );

        result = std::make_pair( ret, distinguished_name );

        return result;
    }

    /**
     * This function generates kerberos ticket with user with access to gMSA password credentials
     * User credentials must have adequate privileges to read gMSA passwords
     * This is an alternative to the machine credentials approach above
     * @param cf_daemon - parent daemon object
     * @return error-code - 0 if successful
     */
    static std::pair<int, std::string> generate_krb_ticket_using_username_and_password(
        std::string domain_name, std::string username, std::string password, CF_logger& cf_logger )
    {
        std::pair<int, std::string> result;

        result = Util::is_kinit_cmd_present();
        if ( result.first != 0 )
        {
            cf_logger.logger( LOG_ERR, result.second.c_str() );
            return result;
        }

        result = Util::is_ldapsearch_cmd_present();
        if ( result.first != 0 )
        {
            cf_logger.logger( LOG_ERR, result.second.c_str() );
            return result;
        }

        std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                        []( unsigned char c ) { return std::toupper( c ); } );

        // kinit using api interface
        char* kinit_argv[3];

        kinit_argv[0] = (char*)"my_kinit";
        username = username + "@" + domain_name;
        kinit_argv[1] = (char*)username.c_str();
        kinit_argv[2] = (char*)password.c_str();
        int ret = my_kinit_main( 2, kinit_argv );
        Util::clearString( username );
        Util::clearString( password );

        result = std::make_pair( ret, "" );

        return result;
    }

    /**
     * If the host is domain-joined, the result is of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
     * @param domain_name: Expected domain name as per configuration
     * @return result pair<int, std::string> (error-code - 0 if successful
     *                          string of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM')
     */
    static std::pair<int, std::string> get_machine_principal( std::string domain_name,
                                                              CF_logger& cf_logger )
    {
        std::pair<int, std::string> result = std::make_pair( -1, "" );

        char hostname[HOST_NAME_MAX];
        int status = gethostname( hostname, HOST_NAME_MAX );
        if ( status )
        {
            result.first = status;
            return result;
        }

        std::pair<int, std::string> realm_name_result = Util::get_realm_name();
        if ( realm_name_result.first != 0 )
        {
            return realm_name_result;
        }

        std::pair<int, std::string> domain_name_result = Util::check_domain_name( domain_name );
        if ( domain_name_result.first != 0 )
        {
            return domain_name_result;
        }

        std::string s = std::string( hostname );
        std::string host_name = s.substr( 0, s.find( '.' ) );

        // truncate the hostname to the host name size limit defined by microsoft
        if ( host_name.length() > HOST_NAME_LENGTH_LIMIT )
        {
            cf_logger.logger( LOG_ERR,
                              "WARNING: %s:%d hostname exceeds 15 characters,"
                              "this can cause problems in getting kerberos tickets, please reduce "
                              "hostname length",
                              __func__, __LINE__ );
            host_name = host_name.substr( 0, HOST_NAME_LENGTH_LIMIT );
            std::cerr << Util::getCurrentTime() << '\t'
                      << "INFO: hostname exceeds 15 characters this can "
                         "cause problems in getting kerberos tickets, "
                         "please reduce hostname length"
                      << std::endl;
        }

        /**
         * Machine principal is of the format EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
         */
        result.first = 0;
        result.second = "'" + host_name + "$@'" + realm_name_result.second;

        return result;
    }
};
