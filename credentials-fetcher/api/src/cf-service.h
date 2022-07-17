#ifndef _cf_service_h_
#define _cf_service_h_

namespace creds_fetcher
{
    class CF_service
    {
      public:
        CF_service();
    };
}
int RunGrpcServer(std::string unix_socket_path, creds_fetcher::CF_logger& cf_logger);

#endif // _cf_service_h_
