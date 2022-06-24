#include <stdio.h>
#include <err.h>
#include <wchar.h>
#include <stddef.h>
#include <locale.h>
#include <stdlib.h>
#include <signal.h>
#include <string>

#include <iostream>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "base64.h"
#include "daemon.h"

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
typedef struct blob_t_ {
    uint16_t version;
    uint16_t reserved;
    uint32_t length;
    uint16_t current_password_offset;
    uint16_t previous_password_offset;
    uint16_t query_password_interval_offset;
    uint16_t unchanged_password_interval_offset;
#define BLOB_REMAINING_BUF_SIZE 1024 /* TBD:: Fix this, remaining buf size is variable */
    uint8_t buf[1024];
    /* TBD:: Add remaining fields here */
} blob_t;

/*
 * This function fetches the gmsa password.
 * It uses existing krb ticket of machine to run ldap query over
 * kerberos and do the appropriate UTF decoding.
 * TBD:: Replace return value after shell command is complete.
 */
void get_krb_ticket(const char *ldap_uri_arg, const char *gmsa_account_name_arg)
{
    /* TBD:: The last shell command is manual for now, this will be replaced */
    if (ldap_uri_arg == NULL || gmsa_account_name_arg == NULL) {
        return;
    }
    std::string ldap_uri(ldap_uri_arg);
    std::string gmsa_arg(gmsa_account_name_arg);
    std::vector<std::string> results;

    boost::split(results, ldapuri, [](char c){return c == '.';});
    std::string domain;
    for (auto it = results.begin(); it != results.end(); it++) {
        domain += "DC=" + *it + ",";
    }
    domain.pop_back(); // Remove last comma

    std::string cmd = std::string("ldapsearch -H ldap://") + ldap_uri;
    std::string gmsa_account_name = gmsa_arg;
        cmd +=    std::string(" -b 'CN=")
            + gmsa_account_name
        + std::string(",CN=Managed Service Accounts,")
        + domain
        + std::string("'")
        + std::string(" -s sub  \"(objectClass=msDs-GroupManagedServiceAccount)\" msDS-ManagedPassword");

    /* ======== [start] TBD: Add better method to shell out commands ======== */
    FILE *fp = popen(cmd.c_str(), "r");
    std::string out;
    char data[80];
    while (fgets(data, 80, fp) != NULL) {
        out += std::string(data);
    }
    fclose(fp);
    /* ======== [end] TBD: Add better method to shell out commands ======== */

    std::string password = std::string("msDS-ManagedPassword::");
    boost::split(results, out, [](char c){return c == '#';});

    for (auto it = results.begin(); it != results.end(); it++) {
        auto found = it->find(password);
            if (found != std::string::npos) {
            found += password.length();
            password = it->substr(found + 1, it->length());
            break;
        }
    }

    size_t out_len;
    unsigned char *blob_dest
        = base64_decode((const unsigned char *)password.c_str(),
                password.length(), &out_len);

    blob_t *blob = ((blob_t *)blob_dest);

    setlocale(LC_CTYPE, "");
    unsigned short *arr = (unsigned short *)blob->buf;

    /* TBD: Remove outfile with in-memory file, passwords must *not* be saved to files */
    FILE *fp1 = fopen("outfile","wb");
    for (int i = 0; i < 256; i++) {
        //wprintf(L"%lc", arr[i]);
        fwprintf(fp1, L"%lc", arr[i]);
    }

#if 0
   /* TBD: Exec the shell cmd below to get the krb ticket, this works manually */
    system("cat outfile | iconv -t utf-8 | kinit -V 'webapp01$'@CONTOSO.COM");
#endif

    return;
}
