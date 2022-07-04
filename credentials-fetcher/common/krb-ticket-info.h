#ifndef _krb_ticket_info_h_
#define _krb_ticket_info_h_

namespace creds_fetcher {
        class krb_ticket_info {
            public:
                    krb_ticket_info();
                    uint64_t lease_id;
                    std::string krb_file_path;
                    std::string service_account_name;
                    std::string domain_name;
        };
}

#endif // _krb_ticket_info_h_
