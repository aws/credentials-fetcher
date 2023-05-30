#include "daemon.h"
#include <boost/filesystem.hpp>
#include <dirent.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <sys/types.h>


// renew the ticket 1 hrs before the expiration
#define RENEW_TICKET_HOURS 1
#define SECONDS_IN_HOUR 3600
// Active Directory uses NetBIOS computer names that do not exceed 15 characters.
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
#define HOST_NAME_LENGTH_LIMIT 15

static const std::string install_path_for_decode_exe =
    "/usr/sbin/credentials_fetcher_utf16_private.exe";
static const std::string install_path_for_aws_cli = "/usr/bin/aws";
static const std::string install_path_for_py_script_base_64_decoding = "/usr/sbin/kube2krb.py";

extern "C" int my_kinit_main(int, char **);

/**
 * Check if binary is writable other than root
 * @param filename - must be owned and writable only by root
 * @return - true or false
 */
bool check_file_permissions( std::string filename )
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

    FILE* pFile = popen( cmd.c_str(), "r" );
    if ( pFile == nullptr )
    {
        std::pair<int, std::string> result = std::pair<int, std::string>( -1, std::string( "" ) );
        return result;
    }

    while ( fgets( line, sizeof( line ), pFile ) != nullptr )
    {
        output += std::string( line );
    }
    int error_code = pclose( pFile );

    std::pair<int, std::string> result = std::pair<int, std::string>( error_code, output );
    return result;
}

/**
 * If the host is domain-joined, the result is of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
 * @param domain_name: Expected domain name as per configuration
 * @return result pair<int, std::string> (error-code - 0 if successful
 *                          string of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM')
 */
static std::pair<int, std::string> get_machine_principal( std::string domain_name, creds_fetcher::CF_logger& cf_logger )
{
    std::pair<int, std::string> result;

    std::pair<int, std::string> hostname_result = exec_shell_cmd( "hostname -s | tr -d '\n'" );
    if ( hostname_result.first != 0 )
    {
        result.first = hostname_result.first;
        return result;
    }

    std::pair<int, std::string> realm_name_result =
        exec_shell_cmd( "realm list | grep  'realm-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
    if ( realm_name_result.first != 0 )
    {
        result.first = realm_name_result.first;
        realm_name_result =
            exec_shell_cmd( "net ads info | grep  'Realm' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
        if ( realm_name_result.first != 0 )
        {
            result.first = realm_name_result.first;
            return result;
        }
    }

    std::pair<int, std::string> domain_name_result =
        exec_shell_cmd( "realm list | grep  'domain-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
    if ( domain_name_result.first != 0 ||
         ( not std::equal( domain_name_result.second.begin(), domain_name_result.second.end(),
                           domain_name.begin() ) ) )
    {
        result.first = -1;
        return result;
    }

    std::string host_name = hostname_result.second;

    // truncate the hostname to the host name size limit defined by microsoft
    if(host_name.length() > HOST_NAME_LENGTH_LIMIT){
        cf_logger.logger( LOG_ERR, "WARNING: %s:%d hostname exceeds 15 characters,"
             "this can cause problems in getting kerberos tickets, please reduce hostname length",
             __func__, __LINE__ );
        host_name = host_name.substr(0,HOST_NAME_LENGTH_LIMIT);
    }

    /**
     * Machine principal is of the format EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
     */
    result.first = 0;
    result.second = host_name + "$@" + realm_name_result.second;

    return result;
}

/**
 * This function generates the kerberos ticket for the host machine.
 * It uses machine keytab located at /etc/krb5.keytab to generate the ticket.
 * @param cf_daemon - parent daemon object
 * @return error-code - 0 if successful
 */
int get_machine_krb_ticket( std::string domain_name, creds_fetcher::CF_logger& cf_logger )
{
    std::pair<int, std::string> result;

    std::pair<int, std::string> cmd = exec_shell_cmd( "which hostname" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which realm" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which kinit" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which ldapsearch" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    if ( !check_file_permissions( install_path_for_decode_exe ) )
    {
        return -1;
    }

    result = get_machine_principal( std::move( domain_name ), cf_logger );
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d invalid machine principal", __func__, __LINE__ );
        return result.first;
    }

    // kinit -kt /etc/krb5.keytab  'EC2AMAZ-GG97ZL$'@CONTOSO.COM
    std::transform( result.second.begin(), result.second.end(), result.second.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string kinit_cmd = "kinit -kt /etc/krb5.keytab '" + result.second + "'";
    result = exec_shell_cmd( kinit_cmd );

    return result.first;
}

/**
 * This function generates kerberos ticket with user credentials
 * User credentials must have adequate privileges to read gMSA passwords
 * This is an alternative to the machine credentials approach above
 * @param cf_daemon - parent daemon object
 * @return error-code - 0 if successful
 */
int get_user_krb_ticket( std::string domain_name, std::string aws_sm_secret_name,
                         creds_fetcher::CF_logger& cf_logger )
{
    std::pair<int, std::string> result;
    int ret;

    std::pair<int, std::string> cmd = exec_shell_cmd( "which hostname" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which kinit" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which ldapsearch" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    if ( !check_file_permissions( install_path_for_decode_exe ) )
    {
        return -1;
    }

    if ( !check_file_permissions( install_path_for_aws_cli ) )
    {
        return -1;
    }

    std::string command =
        install_path_for_aws_cli + std::string( " secretsmanager get-secret-value --secret-id " ) + aws_sm_secret_name + " --query 'SecretString' --output text";
    // /usr/bin/aws secretsmanager get-secret-value --secret-id aws/directoryservices/d-xxxxxxxxxx/gmsa --query 'SecretString' --output text
    result = exec_shell_cmd( command );

    // deserialize json to krb_ticket_info object
    namespace pt = boost::property_tree;
    pt::ptree root;
    // {"username":"user","password":"passw0rd"}
    std::stringstream ss;
    ss << result.second;
    pt::read_json( ss, root );
    std::string username = root.get<std::string>( "username" );
    std::string password = root.get<std::string>( "password" );

    std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );

    // kinit using api interface
    char *kinit_argv[3];

    kinit_argv[0] = (char *)"my_kinit";
    username = username + "@" + domain_name;
    kinit_argv[1] = (char *)username.c_str();
    kinit_argv[2] = (char *)password.c_str();
    ret = my_kinit_main(2, kinit_argv);
#if 0
    /* The old way */
    std::string kinit_cmd = "echo '"  + password +  "' | kinit -V " + username + "@" +
                            domain_name;
    username = "xxxx";
    password = "xxxx";
    result = exec_shell_cmd( kinit_cmd );
    kinit_cmd = "xxxx";
    return result.first;
#endif

    return ret;
}


/**
 * This function generates kerberos ticket with user with access to gMSA password credentials
 * User credentials must have adequate privileges to read gMSA passwords
 * This is an alternative to the machine credentials approach above
 * @param cf_daemon - parent daemon object
 * @return error-code - 0 if successful
 */
int get_domainless_user_krb_ticket( std::string domain_name, std::string username, std::string
                                                                                       password,
                         creds_fetcher::CF_logger& cf_logger )
{
    std::pair<int, std::string> result;
    int ret;

    std::pair<int, std::string> cmd = exec_shell_cmd( "which hostname" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which kinit" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    cmd = exec_shell_cmd( "which ldapsearch" );
    rtrim( cmd.second );
    if ( !check_file_permissions( cmd.second ) )
    {
        return -1;
    }

    std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );

    // kinit using api interface
    char *kinit_argv[3];

    kinit_argv[0] = (char *)"my_kinit";
    username = username + "@" + domain_name;
    kinit_argv[1] = (char *)username.c_str();
    kinit_argv[2] = (char *)password.c_str();
    ret = my_kinit_main(2, kinit_argv);
    username = "xxxx";
    password = "xxxx";

    //TODO: nit - return pair later
    return ret;
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
    boost::split( results, ldap_search_result, []( char c ) { return c == '#'; } );

    bool password_found = false;
    for ( auto& result : results )
    {
        auto found = result.find( password );
        if ( found != std::string::npos )
        {
            found += password.length();
            password = result.substr( found + 1, result.length() );
            // std::cout << "Password = " << password << std::endl;
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
            std::cout << "ERROR: base64 buffer is null" << std::endl;
            return std::make_pair( 0, nullptr );
        }
    }

    return std::make_pair( base64_decode_len, blob_base64_decoded );
}

/**
 * UTF-16 diagnostic: Test utf16 capability
 * @return - true (pass) or false (fail)
 */
int test_utf16_decode()
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
        0xE8, 0xB3, 0x88, 0xE2, 0xAA, 0x84, 0xEB, 0xB8, 0x9F, 0xE5, 0x86, 0x8D, 0xE4, 0xA7, 0xA2,
        0xE6, 0x88, 0x95, 0xEF, 0xB5, 0xAE, 0xE1, 0xB1, 0xA9, 0xE5, 0x86, 0xAC, 0xEA, 0xB3, 0x83,
        0xEF, 0xBF, 0xBD, 0xE1, 0xB9, 0xA1, 0xE9, 0xBB, 0xB3, 0xE1, 0x8F, 0x86, 0xE5, 0x9D, 0x93,
        0xE9, 0x9F, 0x92, 0xE7, 0xB4, 0x82, 0xEF, 0x81, 0xAF, 0xE0, 0xB0, 0x86, 0xE5, 0xA4, 0xB7,
        0xE0, 0xAD, 0x8C, 0xE7, 0xAB, 0xB5, 0xE4, 0x9D, 0x9B, 0xE5, 0x99, 0x99, 0xE1, 0x86, 0xB4,
        0xE6, 0x9A, 0xA4, 0xE1, 0x89, 0xBF, 0xEA, 0x8B, 0xB5, 0xE7, 0x8B, 0x9F, 0xEF, 0xBF, 0xBD,
        0xE1, 0x84, 0x9A, 0xCF, 0xA4, 0xE2, 0x95, 0xAE, 0xEB, 0x9B, 0xBE, 0xE9, 0x93, 0x9C, 0xE8,
        0xBC, 0x91, 0xE4, 0xB1, 0xBA, 0x65, 0xE4, 0x81, 0xAA, 0xE6, 0x8E, 0xB4, 0xE8, 0x8D, 0x86,
        0xE5, 0x83, 0xA7, 0xE1, 0xA2, 0x96, 0xE7, 0xBB, 0xB0, 0xE6, 0xA7, 0xB8, 0xEA, 0xB1, 0x9C,
        0xE4, 0xAD, 0xBF, 0xED, 0x91, 0xBE, 0xE2, 0x9B, 0x8D, 0xEB, 0xA6, 0xA0, 0xED, 0x80, 0xA6,
        0xED, 0x8A, 0x83, 0xE1, 0xB8, 0x88, 0xE3, 0x89, 0xB6, 0xC9, 0xAD, 0xED, 0x9C, 0x8B, 0xE4,
        0xB7, 0xA5, 0xCC, 0xBD, 0xEA, 0x9B, 0xB4, 0xF0, 0xA5, 0x9F, 0x8B, 0xE5, 0xAB, 0xA0, 0xEB,
        0xB5, 0xA0, 0xE5, 0xA2, 0x8A, 0xEE, 0x92, 0xA0, 0xE5, 0x88, 0xAF, 0xE7, 0x91, 0xA7, 0xEE,
        0x95, 0x90, 0xEF, 0xBF, 0xBD, 0xE3, 0xBC, 0xB9, 0xE5, 0x9D, 0xB6, 0xEF, 0x8E, 0x8C, 0xED,
        0x98, 0xB4, 0xE1, 0x8A, 0x8D, 0xE7, 0x87, 0xB9, 0xEF, 0x8F, 0x87, 0xEF, 0xBF, 0xBD, 0xEF,
        0x85, 0xA9, 0xE0, 0xB2, 0xA9, 0xE5, 0xB8, 0x92, 0xED, 0x86, 0x96, 0xEE, 0x8C, 0x93, 0xE9,
        0x83, 0x96, 0xEA, 0xAF, 0x9B, 0xE5, 0xAC, 0x9B, 0xE9, 0x86, 0xA4, 0xE8, 0xA1, 0x90, 0xE1,
        0xB6, 0xB4, 0xE7, 0x93, 0xAC, 0xE4, 0xA9, 0xA5, 0xE0, 0xBD, 0x86, 0xE1, 0x89, 0xB8, 0xDE,
        0x83, 0xEF, 0xAB, 0x9A, 0xE8, 0xAC, 0x88, 0xE4, 0x85, 0xAB, 0xE3, 0xB0, 0xBA, 0xEE, 0xAA,
        0x8F, 0xE2, 0x95, 0xA0, 0xE7, 0xA3, 0xB0, 0xD7, 0xBB, 0xE3, 0xA5, 0x9B, 0xE6, 0xB9, 0x86,
        0xE7, 0xA8, 0xB1, 0xE9, 0x83, 0x8A, 0xE6, 0x84, 0xB5, 0xE7, 0x97, 0xB1, 0xE5, 0x80, 0x8E,
        0xE4, 0x98, 0x97, 0xE3, 0xA6, 0x87, 0xEB, 0x97, 0xA7, 0xEA, 0x9C, 0x95, 0xEC, 0xB4, 0x8C,
        0xE8, 0x9E, 0x83, 0xE6, 0xA0, 0x80, 0xE4, 0xA0, 0x94, 0xDA, 0xAC, 0xE7, 0x9E, 0xBD, 0xE5,
        0xAB, 0x9D, 0xE6, 0xA4, 0xBC, 0xE1, 0xB8, 0x97, 0xE8, 0xA9, 0xB5, 0xE3, 0x9A, 0xB0, 0xEC,
        0xAC, 0xBF, 0xEC, 0xA8, 0x92, 0xE9, 0xA3, 0xA2, 0xE5, 0xA9, 0x82, 0xEE, 0x99, 0xBA };

    std::string decoded_password_file = "./decoded_password_file";

    std::pair<size_t, void*> base64_decoded_password_blob =
        find_password( test_msds_managed_password );
    if ( base64_decoded_password_blob.first == 0 || base64_decoded_password_blob.second == nullptr )
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
    creds_fetcher::blob_t* blob = ( (creds_fetcher::blob_t*)base64_decoded_password_blob.second );
    FILE* fp = popen( decode_cmd.c_str(), "w" );
    if ( fp == nullptr )
    {
        std::cout << "Self test failed" << std::endl;
        OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
        OPENSSL_free( base64_decoded_password_blob.second );
        return EXIT_FAILURE;
    }
    fwrite( blob->current_password, 1, GMSA_PASSWORD_SIZE, fp );
    if ( pclose( fp ) < 0 )
    {
        std::cout << "Self test failed" << std::endl;
        OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
        OPENSSL_free( base64_decoded_password_blob.second );
        return EXIT_FAILURE;
    }

    fp = fopen( decoded_password_file.c_str(), "rb" );
    if ( fp == nullptr )
    {
        std::cout << "Self test failed" << std::endl;
        OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
        OPENSSL_free( base64_decoded_password_blob.second );
        return EXIT_FAILURE;
    }
    fread( test_password_buf, 1, GMSA_PASSWORD_SIZE, fp );

    if ( memcmp( test_gmsa_utf8_password, test_password_buf, GMSA_PASSWORD_SIZE ) == 0 )
    {
        // utf16->utf8 conversion works as expected
        std::cout << "Self test is successful" << std::endl;
        OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
        OPENSSL_free( base64_decoded_password_blob.second );
        unlink( decoded_password_file.c_str() );
        return EXIT_SUCCESS;
    }

    std::cout << "Self test failed" << std::endl;
    OPENSSL_cleanse( base64_decoded_password_blob.second, base64_decoded_password_blob.first );
    OPENSSL_free( base64_decoded_password_blob.second );
    unlink( decoded_password_file.c_str() );
    return EXIT_FAILURE;
}

/**
 * Get list of domain-ips representing a domain
 * @param domain_name Like 'contoso.com'
 * @return - Pair of result and string, 0 if successful and FQDN like win-m744.contoso.com
 */
std::pair<int, std::vector<std::string>> get_domain_ips( std::string domain_name )
{
    std::vector<std::string> list_of_ips = { "" };

    /**
     * TBD:: change shell commands to using api
     */
    std::string cmd = "dig +noall +answer " + domain_name + " | awk '{ print $5 }'";

    std::pair<int, std::string> ips = exec_shell_cmd( cmd );
    if ( ips.first != 0 )
    {
        return std::make_pair( ips.first, list_of_ips );
    }

    boost::split( list_of_ips, ips.second, []( char c ) { return c == '\n'; } );

    return std::make_pair( EXIT_SUCCESS, list_of_ips );
}

/**
 * DNS reverse lookup, given IP, return domain name
 * @param domain_name Like 'contoso.com'
 * @return - Pair of result and string, 0 if successful and FQDN like win-m744.contoso.com
 */
std::pair<int, std::string> get_fqdn_from_domain_ip( std::string domain_ip,
                                                     std::string domain_name )
{
    /**
     * We expect fqdns to have hostnames, only the second entry is picked from below.
     * $ dig -x 172.32.157.20 +noall +short +answer
     * contoso.com.
     * win-cqec6o8gd7i.contoso.com.
     */
    std::string cmd = "dig -x " + domain_ip + " +noall +answer +short | grep -v ^" + domain_name;

    std::pair<int, std::string> reverse_dns_output = exec_shell_cmd( cmd );
    if ( reverse_dns_output.first != 0 )
    {
        return std::make_pair( reverse_dns_output.first, std::string( "" ) );
    }

    std::vector<std::string> list_of_dc_names;
    boost::split( list_of_dc_names, reverse_dns_output.second, []( char c ) { return c == '\n'; } );

    for ( auto fqdn_str : list_of_dc_names )
    {
        if ( fqdn_str.length() == 0 )
        {
            return std::make_pair( EXIT_FAILURE, "" );
        }
        fqdn_str.pop_back(); // Remove trailing .

        /**
         * We can ignore DNS resolution like ip-10-0-0-162.us-west-1.compute.internal
         * since it does not have a domain such as "contoso.com"
         */
        if ( !fqdn_str.empty() && ( fqdn_str.find( domain_name ) != std::string::npos ) )
        {
            return std::make_pair( EXIT_SUCCESS, fqdn_str );
        }
    }

    return std::make_pair( EXIT_FAILURE, "" );
}

/**
 * This function fetches the gmsa password and creates a krb ticket
 * It uses the existing krb ticket of machine to run ldap query over
 * kerberos and do the appropriate UTF decoding.
 *
 * @param domain_name - Like 'contoso.com'
 * @param gmsa_account_name - Like 'webapp01'
 * @param krb_cc_name - Like '/var/credentials_fetcher/krb_dir/krb5_cc'
 * @param cf_logger - log to systemd daemon
 * @return result code and kinit log, 0 if successful, -1 on failure
 */
std::pair<int, std::string> get_gmsa_krb_ticket( std::string domain_name,
                                                 const std::string& gmsa_account_name,
                                                 const std::string& krb_cc_name,
                                                 creds_fetcher::CF_logger& cf_logger )
{
    std::vector<std::string> results;

    if ( domain_name.empty() || gmsa_account_name.empty() )
    {
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d null args", __func__, __LINE__ );
        return std::make_pair( -1, std::string( "" ) );
    }

    boost::split( results, domain_name, []( char c ) { return c == '.'; } );
    std::string base_dn; /* Distinguished name */
    for ( auto& result : results )
    {
        base_dn += "DC=" + result + ",";
    }
    base_dn.pop_back(); // Remove last comma

    std::pair<int, std::vector<std::string>> domain_ips = get_domain_ips( domain_name );
    if ( domain_ips.first != 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR: Cannot resolve domain IPs of %s", __func__, __LINE__,
                          domain_name );
        return std::make_pair( -1, std::string( "" ) );
    }

    std::string fqdn;
    for ( auto domain_ip : domain_ips.second )
    {
        auto fqdn_result = get_fqdn_from_domain_ip( domain_ip, domain_name );
        if ( fqdn_result.first == 0 )
        {
            fqdn = fqdn_result.second;
            break;
        }
    }
    if ( fqdn.empty() )
    {
        std::cout << "************ERROR***********" << std::endl;
        return std::make_pair( -1, std::string( "" ) );
    }

    /**
     * ldapsearch -H ldap://<fqdn> -b 'CN=webapp01,CN=Managed Service
     *   Accounts,DC=contoso,DC=com' -s sub  "(objectClass=msDs-GroupManagedServiceAccount)"
     *   msDS-ManagedPassword
     */
    std::string cmd = std::string( "ldapsearch -H ldap://" ) + fqdn;
    cmd += std::string( " -b 'CN=" ) + gmsa_account_name +
           std::string( ",CN=Managed Service Accounts," ) + base_dn + std::string( "'" ) +
           std::string( " -s sub  \"(objectClass=msDs-GroupManagedServiceAccount)\" "
                        " msDS-ManagedPassword" );

    cf_logger.logger( LOG_INFO, "%s", cmd );
    std::cout << cmd << std::endl;
    std::pair<int, std::string> ldap_search_result = exec_shell_cmd( cmd );
    if ( ldap_search_result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d ldapsearch failed", __func__, __LINE__ );
        return std::make_pair( -1, std::string( "" ) );
    }

    std::pair<size_t, void*> password_found_result = find_password( ldap_search_result.second );

    if ( password_found_result.first == 0 || password_found_result.second == nullptr )
    {
        std::cout << "ERROR: Password not found" << std::endl;
        return std::make_pair( -1, std::string( "" ) );
    }

    creds_fetcher::blob_t* blob = ( (creds_fetcher::blob_t*)password_found_result.second );
    auto* blob_password = (uint8_t*)blob->current_password;

    std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string default_principal = "'" + gmsa_account_name + "$'" + "@" + domain_name;

    /* Pipe password to the utf16 decoder and kinit */
    std::string kinit_cmd = std::string("dotnet ") + std::string( install_path_for_decode_exe ) +
                            std::string( " | kinit " ) + std::string( " -c " ) + krb_cc_name +
                            " -V " + default_principal;
    std::cout << kinit_cmd << std::endl;
    FILE* fp = popen( kinit_cmd.c_str(), "w" );
    if ( fp == nullptr )
    {
        perror( "kinit failed" );
        OPENSSL_cleanse( password_found_result.second, password_found_result.first );
        OPENSSL_free( password_found_result.second );
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d kinit failed", __func__, __LINE__ );
        return std::make_pair( -1, std::string( "" ) );
    }
    fwrite( blob_password, 1, GMSA_PASSWORD_SIZE, fp );
    int error_code = pclose( fp );

    // kinit output
    std::cout << "kinit return value = " << error_code << std::endl;

    OPENSSL_cleanse( password_found_result.second, password_found_result.first );
    OPENSSL_free( password_found_result.second );

    return std::make_pair( error_code, krb_cc_name );
}

/**
 * Checks if the given ticket needs renewal or recreation
 * @param krb_cc_name  - Like '/var/credentials_fetcher/krb_dir/krb5_cc'
 * @return - is renewal needed - true or false
 */

bool is_ticket_ready_for_renewal( std::string krb_cc_name )
{
    std::string cmd = "export KRB5CCNAME=" + krb_cc_name + " &&  klist";
    std::pair<int, std::string> krb_ticket_info_result = exec_shell_cmd( cmd );
    if ( krb_ticket_info_result.first != 0 )
    {
        // we need to check if meta file exists to recreate the ticket
        return false;
    }

    std::vector<std::string> results;

    boost::split( results, krb_ticket_info_result.second, []( char c ) { return c == '#'; } );
    std::string renew_until = "renew until";
    bool is_ready_for_renewal = false;

    for ( auto& result : results )
    {
        auto found = result.find( renew_until );
        if ( found != std::string::npos )
        {
            found += renew_until.length();
            std::string renewal_date_time = result.substr( found + 1, result.length() );

            char renewal_date[80];
            char renewal_time[80];

            sscanf( renewal_date_time.c_str(), "%s %s", renewal_date, renewal_time );

            renew_until = std::string( renewal_date ) + " " + std::string( renewal_time );
            // trim extra spaces
            ltrim( renew_until );
            rtrim( renew_until );

            // next renewal time for the ticket
            struct tm tm;

            // if the string is not date time format, return false
            if ( strptime( renew_until.c_str(), "%m/%d/%Y %T", &tm ) == NULL )
                return false;

            std::time_t next_renewal_time = mktime( &tm );

            // get the current system time
            std::time_t t = std::time( NULL );
            std::tm* now = std::localtime( &t );
            std::time_t current_time = mktime( now );

            // calculate the time difference in hours
            double hours = std::difftime( next_renewal_time, current_time ) / SECONDS_IN_HOUR;

            // check of the ticket need to be renewed
            if ( hours <= RENEW_TICKET_HOURS )
            {
                is_ready_for_renewal = true;
            }
            break;
        }
    }

    return is_ready_for_renewal;
}

/**
 * This function does the ticket renewal in domainless mode.
 * @param krb_files_dir
 * @param domain_name
 * @param username
 * @param password
 */
std::list<std::string> renew_kerberos_tickets_domainless(std::string krb_files_dir, std::string
                                                                                         domain_name,
                                               std::string username, std::string password,
                                               creds_fetcher::CF_logger& cf_logger )
{
    std::list<std::string> renewed_krb_ticket_paths;
    // identify the metadata files in the krb directory
    std::vector<std::string> metadatafiles;
    for ( boost::filesystem::recursive_directory_iterator end, dir( krb_files_dir );
          dir != end; ++dir )
    {
        auto path = dir->path();
        if ( boost::filesystem::is_regular_file( path ) )
        {
            // find the file with metadata extension
            std::string filename = path.filename().string();
            if ( !filename.empty() && filename.find( "_metadata" ) != std::string::npos )
            {
                std::string filepath = path.parent_path().string() + "/" + filename;
                metadatafiles.push_back( filepath );
            }
        }
    }

    // read the information of service account from the files
    for ( auto file_path : metadatafiles )
    {
        std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list =
            read_meta_data_json( file_path );

        // refresh the kerberos tickets for the service accounts, if tickets ready for
        // renewal
        for ( auto krb_ticket : krb_ticket_info_list )
        {
            std::string domainlessuser = krb_ticket->domainless_user;
            if(!username.empty()  && username == domainlessuser)
            {
                std::pair<int, std::string> gmsa_ticket_result;
                std::string krb_cc_name = krb_ticket->krb_file_path;
                // gMSA kerberos ticket generation needs to have ldap over kerberos
                // if the ticket exists for the machine/user already reuse it for getting gMSA password else retry the ticket creation again after generating user/machine kerberos ticket
                int num_retries = 2;
                for ( int i = 0; i < num_retries; i++ )
                {
                    gmsa_ticket_result = get_gmsa_krb_ticket( krb_ticket->domain_name,
                                                              krb_ticket->service_account_name,
                                                              krb_cc_name, cf_logger );
                    if ( gmsa_ticket_result.first != 0 )
                    {
                        if ( num_retries == 0 )
                        {
                            cf_logger.logger( LOG_WARNING,
                                              "WARNING: Cannot get gMSA krb ticket "
                                              "because of expired user/machine ticket, "
                                              "will be retried automatically" );
                        }
                        else
                        {
                            cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket" );
                        }
                        // if tickets are created in domainless mode
                        std::string domainless_user = krb_ticket->domainless_user;
                        if ( !domainless_user.empty() && domainless_user == username )
                        {
                            int status = get_domainless_user_krb_ticket( domain_name, username,
                                                                         password, cf_logger );

                            if ( status < 0 )
                            {
                                cf_logger.logger( LOG_ERR, "Error %d: Cannot get user krb ticket",
                                                  status );
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        renewed_krb_ticket_paths.push_back( krb_cc_name );
                        i++;
                    }
                }
            }
        }
    }

    return renewed_krb_ticket_paths;
}

/**
 * delete kerberos ticket corresponding to lease id
 * @param krb_files_dir - path to kerberos directory
 * @param lease_id - lease_id associated to kerberos tickets
 * @return - vector of kerberos deleted paths
 */
std::vector<std::string> delete_krb_tickets( std::string krb_files_dir, std::string lease_id )
{
    std::vector<std::string> delete_krb_ticket_paths;
    if ( lease_id.empty() || krb_files_dir.empty() )
        return delete_krb_ticket_paths;

    std::string krb_tickets_path = krb_files_dir + "/" + lease_id;

    DIR* curr_dir;
    struct dirent* file;
    // open the directory
    curr_dir = opendir( krb_tickets_path.c_str() );
    try
    {
        if ( curr_dir )
        {
            while ( ( file = readdir( curr_dir ) ) != NULL )
            {
                std::string filename = file->d_name;
                if ( !filename.empty() && filename.find( "_metadata" ) != std::string::npos )
                {
                    std::string file_path = krb_tickets_path + "/" + filename;
                    std::list<creds_fetcher::krb_ticket_info*> krb_ticket_info_list =
                        read_meta_data_json( file_path );

                    for ( auto krb_ticket : krb_ticket_info_list )
                    {
                        std::string krb_file_path = krb_ticket->krb_file_path;
                        std::string cmd = "export KRB5CCNAME=" + krb_file_path + " && kdestroy";

                        std::pair<int, std::string> krb_ticket_destroy_result =
                            exec_shell_cmd( cmd );
                        if ( krb_ticket_destroy_result.first == 0 )
                        {
                            delete_krb_ticket_paths.push_back( krb_file_path );
                        }
                        else
                        {
                            // log ticket deletion failure
                            std::cout << "Delete kerberos ticket failed" + krb_file_path
                                      << std::endl;
                        }
                    }
                }
            }
            // close directory
            closedir( curr_dir );

            // finally delete lease file and directory
            boost::filesystem::remove_all( krb_tickets_path );
        }
    }
    catch ( ... )
    {
        fprintf( stderr, SD_CRIT "deleting kerberos tickets failed" );
        closedir( curr_dir );
        return delete_krb_ticket_paths;
    }
    return delete_krb_ticket_paths;
}

/**
 * trim from start (in place)
 * @param s - string input
 */
void ltrim( std::string& s )
{
    s.erase( s.begin(), std::find_if( s.begin(), s.end(),
                                      []( unsigned char ch ) { return !std::isspace( ch ); } ) );
}

/**
 * trim from end (in place)
 * @param s - string input
 */
void rtrim( std::string& s )
{
    s.erase(
        std::find_if( s.rbegin(), s.rend(), []( unsigned char ch ) { return !std::isspace( ch ); } )
            .base(),
        s.end() );
}

/** All kubernetes gMSA support work **/
/**
 * This function parses the kube config file
 * The cred spec file is in json format.
 * @param kubeconfigpath - kubeconfig path
 * @param krb_ticket_info - return service account info
 * @return
 */
std::list<creds_fetcher::kube_config_info*> parse_kube_config( std::string kubeFilePath,
                                                              std::string krbdir )
{
    std::list<creds_fetcher::kube_config_info*> kube_config_info_list;
    try
    {
        if ( kubeFilePath.empty() )
        {
            fprintf( stderr, SD_CRIT "kube file is empty" );
            return kube_config_info_list;
        }

        namespace pt = boost::property_tree;
        pt::ptree root;
        std::istringstream credspec_stream( kubeFilePath );
        pt::read_json( kubeFilePath, root );

        std::string lease_id = generate_lease_id();
        const pt::ptree& child_tree_gmsa =
            root.get_child( "gmsa_secrets_to_kube_secrets_mappings.ServiceAccountMappings" );
        for ( auto& kv : child_tree_gmsa )
        {
            creds_fetcher::kube_config_info* kube_config_info =  new creds_fetcher::kube_config_info;
            creds_fetcher::krb_ticket_info* krb_ticket_info =
                new creds_fetcher::krb_ticket_info;
            std::string credentialspecpath = kv.second.get<std::string>( "path_to_cred_spec_json" );

            int status = parse_cred_spec( credentialspecpath, krb_ticket_info, true );
            if(status != -1)
            {
                if(!krb_ticket_info->krb_file_path.empty())
                {
                    krb_ticket_info->krb_file_path =
                        krbdir + "/" + lease_id + "/" + krb_ticket_info->service_account_name;
                }
                krb_ticket_info->domainless_user = kv.second.get<std::string>( "domainless_user" );
            }
            //kv.second.put<std::string>("krb_ticket_location", krb_ticket_info->krb_file_path);
            kube_config_info->krb_ticket_info = krb_ticket_info;

            std::list<std::string> secret_yaml_paths;
            for ( const auto& sv : kv.second)
            {
                secret_yaml_paths.push_back(sv.second.get<std::string>("path_to_kube_secret_yaml"));
            }
            kube_config_info->secret_yaml_paths = secret_yaml_paths;
            kube_config_info_list.push_back(kube_config_info);
        }
        pt::write_json( kubeFilePath, root );
    }
    catch ( ... )
    {
        fprintf( stderr, SD_CRIT "kubeconfig file is not properly formatted" );
        return kube_config_info_list;
    }
    return kube_config_info_list;
}

/*
 * #f=open("/var/credentials-fetcher/krbdir/434d760fade0559999d6/WebApp01/krb5cc","rb")
 */
/*
 * convert_secret_krb2kube : Update secret in kube file for secret by importing from krb ticket
 */
std::pair<int, std::string> convert_secret_krb2kube(const std::string kube_secrets_yaml_file,
                                                     const std::string krb_ticket_file )
{
    FILE* fp = fopen( install_path_for_py_script_base_64_decoding.c_str(), "w" );
    if ( fp == NULL || kube_secrets_yaml_file.empty() || krb_ticket_file.empty() )
    {
        return std::make_pair( -1, std::string( "ERROR: parameters" ) );
    }
    //fwrite( kube2krb_script, sizeof( char ), strlen(kube2krb_script), fp );
    fclose( fp );

    std::pair<int, std::string> cmd_result =
        exec_shell_cmd( std::string( "chmod +x " ) + install_path_for_py_script_base_64_decoding );
    if ( cmd_result.first != 0 )
    {
        return std::make_pair( -1, std::string( "ERROR: chmod" ) );
    }

    std::string cmd = "python3 " + install_path_for_py_script_base_64_decoding + " " + kube_secrets_yaml_file + " " + krb_ticket_file;
    return exec_shell_cmd( cmd );
}
