#include "daemon.h"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <locale>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

/**
 * TBD:: Add wrapper around base64.h for C++ to C linkage
 */
extern "C" uint8_t* base64_decode( const uint8_t*, size_t, size_t* );

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
 * @return result pair(error-code, string of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM')
 */
static std::pair<int, std::string> get_machine_principal()
{
    std::pair<int, std::string> result;

    std::pair<int, std::string> hostname_result = exec_shell_cmd( "hostname -s" );
    if ( hostname_result.first != 0 )
    {
        result.first = hostname_result.first;
        return result;
    }

    std::pair<int, std::string> realm_name_result =
        exec_shell_cmd( "realm list | grep  'realm-name' | cut -f2 -d: | tr -d ' '" );
    if ( realm_name_result.first != 0 )
    {
        result.first = realm_name_result.first;
        return result;
    }

    /*
     * Machine principal is of the format EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
     */
    result.first = 0;
    result.second = hostname_result.second + "$@" + realm_name_result.second;

    return result;
}

/**
 * This function generates the kerberos ticket for the host machine.
 * It uses machine keytab located at /etc/krb5.keytab to generate the ticket.
 * @param krb_ccname
 * @return result pair(error-code, shell cmd output)
 */

int generate_host_machine_krb_ticket( const char* krb_ccname )
{
    std::pair<int, std::string> shell_result;

    std::string set_krb5ccname_cmd = "export KRB5CCNAME=" + std::string( krb_ccname );
    // generate kerberos ticket for the host machine
    std::pair<int, std::string> machine_principal = get_machine_principal();
    if ( machine_principal.first != 0 )
    {
        return machine_principal.first;
    }

    std::string kinit_cmd =
        set_krb5ccname_cmd + " && " + "kinit -k '" + machine_principal.second + "'";
    shell_result = exec_shell_cmd( kinit_cmd);

    return shell_result.first;
}

/**
 * Replace certain characters that do not have mappings in UTF-16
 * @param input_blob_buf - Buffer from ldap query
 * @param input_blob_buf_sz - size of buffer
 * @return - returns 0 if successful, -1 on error
 */
int fixup_utf16( uint8_t* input_blob_buf, int32_t input_blob_buf_sz )
{
    if (input_blob_buf == nullptr || input_blob_buf_sz == 0) {
        return -1;
    }

    /**
     * In UTF-16, characters in ranges U+0000—U+D7FF and U+E000—U+FFFD are
     * stored as a single 16 bits unit.
     */
    auto codepoints = (uint16_t*)input_blob_buf;
    for ( int i = 0; i < input_blob_buf_sz; i++ )
    {
        /**
         * U+D800 to U+DFFF As per, https://en.wikipedia.org/wiki/UTF-16, the
         * Unicode standard permanently reserves these code point values for
         * UTF-16 encoding of the high and low surrogates, and they will never be
         * assigned a character, so there should be no reason to encode them. The
         * official Unicode standard says that no UTF forms, including UTF-16,
         * can encode these code points.
         * For example: (0xdef0 -> 0xfffd) (0xde6f -> 0xfffd)
         *              (0xd82d -> 0xfffd) (0xda34 -> 0xfffd)
         **/
        if ( ( codepoints[i] & 0xf800 ) == 0xd800 )
        {
            codepoints[i] = 0xfffd;
        }
    }
    return 0;
}

/**
 * This function fetches the gmsa password.
 * It uses existing krb ticket of machine to run ldap query over
 * kerberos and do the appropriate UTF decoding.
 * TBD:: Replace return value after shell command is complete.
 * @param ldap_uri_arg like "contoso.com"
 * @param gmsa_account_name_arg like "webapp01"
 * @return result code, 0 if successful, -1 on failure
 */
int get_krb_ticket( const char* ldap_uri_arg, const char* gmsa_account_name_arg )
{
    if ( ldap_uri_arg == nullptr || gmsa_account_name_arg == nullptr )
    {
        printf( "**ERROR*%s:%d\n", __func__, __LINE__ );
        return -1;
    }

    std::string ldap_uri( ldap_uri_arg );
    std::string gmsa_arg( gmsa_account_name_arg );
    std::vector<std::string> results;

    boost::split( results, ldap_uri, []( char c ) { return c == '.'; } );
    std::string domain;
    for (auto & result : results)
    {
        domain += "DC=" + result + ",";
    }
    domain.pop_back(); // Remove last comma

    // ldapsearch -H ldap://contoso.com -b 'CN=webapp01,CN=Managed Service
    // Accounts,DC=contoso,DC=com' -s sub  "(objectClass=msDs-GroupManagedServiceAccount)"
    // msDS-ManagedPassword

    std::string cmd = std::string( "ldapsearch -H ldap://" ) + ldap_uri;
    const std::string& gmsa_account_name(gmsa_arg);
    cmd += std::string( " -b 'CN=" ) + gmsa_account_name +
           std::string( ",CN=Managed Service Accounts," ) + domain + std::string( "'" ) +
           std::string( " -s sub  \"(objectClass=msDs-GroupManagedServiceAccount)\" "
                        " msDS-ManagedPassword" );

    std::pair<int, std::string> ldap_search_result = exec_shell_cmd( cmd );
    if ( ldap_search_result.first != 0 )
    {
        printf( "**ERROR*%s:%d\n", __func__, __LINE__ );
        return -1;
    }

    std::string password = std::string( "msDS-ManagedPassword::" );
    boost::split( results, ldap_search_result.second, []( char c ) { return c == '#'; } );

    for (auto & result : results)
    {
        auto found = result.find( password );
        if ( found != std::string::npos )
        {
            found += password.length();
            password = result.substr( found + 1, result.length() );
            break;
        }
    }

    size_t base64_decode_len;
    size_t len = password.length();
    const auto* password_str = (const uint8_t*)password.c_str();
    uint8_t* blob_base64_decoded = base64_decode( password_str, len, &base64_decode_len );
    creds_fetcher::blob_t* blob = ( (creds_fetcher::blob_t*)blob_base64_decoded );

    fixup_utf16( blob->buf, BLOB_REMAINING_BUF_SIZE );

    auto* blob_password = (uint8_t*)blob->buf;

    // TBD: Move /var/log to dir in options file
    char gmsa_password_file[PATH_MAX];
    // TBD: Change the path to dir from config
    char gmsa_passwd_path[] = "/home/ubuntu/code/tmp/gmsa_XXXXXX";
    strncpy( gmsa_password_file, gmsa_passwd_path, strlen(gmsa_passwd_path));
    if ( mkstemp( gmsa_password_file ) < 0 )
    {
        printf( "**ERROR*%s:%d\n", __func__, __LINE__ );
        return -1;
    }
    FILE* fp = fopen( gmsa_password_file, "wb" );
    for ( int i = 0; i < GMSA_PASSWORD_SIZE; i++ )
    {
        fprintf( fp, "%c", blob_password[i] );
    }
    fclose( fp );

    std::transform( ldap_uri.begin(), ldap_uri.end(), ldap_uri.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string default_principal = std::string( gmsa_account_name_arg ) + "$@" + ldap_uri;
    std::string kinit_cmd = std::string( "cat " ) + std::string( gmsa_password_file ) +
                            std::string( " | iconv -f utf-16 -t utf-8 | kinit -V '" ) +
                            default_principal + "'";
    std::pair<int, std::string> result = exec_shell_cmd( kinit_cmd );
    if ( result.first != 0 )
    {
        unlink( gmsa_password_file );
        std::cout << "**ERROR kinit failed:" << result.second;
        return result.first;
    }

    unlink( gmsa_password_file );
    return result.first;
}

/**
 * This function does the ticket re-creation.
 * TBD:: update the in memory db about the status of the ticket.
 * @param ldap_uri_arg like "contoso.com"
 * @param gmsa_account_name_arg like "webapp01"
 * @param krb_ccname file path like "/tmp/krb5ccname0
 */
void krb_ticket_creation( const char* ldap_uri_arg, const char* gmsa_account_name_arg,
                          const char* krb_ccname )
{
    // TBD: uncomment ticket generation once the implementation is done
    generate_host_machine_krb_ticket( "" );
    // get_krb_ticket(ldap_uri_arg, gmsa_account_name_arg);
}

/**
 * This function does the ticket renewal.
 * TBD:: update the in memory db about the status of the ticket.
 * @param defaultprincipal
 * @param krb_ccname
 */
void krb_ticket_renewal( const char* defaultprincipal, const char* krb_ccname )
{
    // set krb cache location krb5ccname
    if ( ( krb_ccname != nullptr ) && ( krb_ccname[0] == '\0' ) )
    {
        std::string set_Krb5ccname_cmd = "export KRB5CCNAME=" + std::string( krb_ccname );
        exec_shell_cmd( set_Krb5ccname_cmd );
    }

    std::string krb_ticket_refresh = "kinit -R " + std::string( defaultprincipal );
    system( krb_ticket_refresh.c_str() );
}
