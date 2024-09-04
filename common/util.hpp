#include "constants.h"
#include <cstdio>
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

    static std::pair<int, std::string> get_FQDN( std::string domain_name )
    {
        /**
         * Find ptr record:
         *    "The PTR or "pointer" DNS record type maps an IP address to a domain name in the DNS.
         *     This is called a DNS reverse lookup."
         *  https://www.nslookup.io/learning/dns-record-types/ptr/
         */
        std::string cmd = "dig ptr " + domain_name + " | grep -C1 'AUTHORITY SECTION' | grep -v 'AUTHORITY SECTION' | awk '{ print $5 }'";
        cmd.pop_back();

        std::pair<int, std::string> reverse_dns_output = Util::exec_shell_cmd( cmd );
        if ( reverse_dns_output.first != 0 )
        {
            cmd = "nslookup -q=ptr " + domain_name + " grep origin | awk -F= '{print $2}' | sed 's/^[ ]*//g";
            std::pair<int, std::string> reverse_dns_output = Util::exec_shell_cmd( cmd );
            if ( reverse_dns_output.first == 0 )
            {
               return reverse_dns_output;
            }
            return std::make_pair( reverse_dns_output.first, std::string( "" ) );
        }

        return reverse_dns_output;
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

    static void set_ecs_mode( bool mode )
    {
        extern bool ecs_mode;
        ecs_mode = mode;
    }

    static bool is_ecs_mode()
    {
        extern bool ecs_mode;
        return ecs_mode;
    }
};
