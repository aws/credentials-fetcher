#include <systemd/sd-journal.h>

#ifndef _cf_logger_h_
#define _cf_logger_h_

namespace creds_fetcher {
        class CF_logger {
                /* TBD:: Fill this later */

                public:
                        int log_level = LOG_NOTICE;

                        /* systemd uses log levels from syslog */
                        void set_log_level(int _log_level)  {
                            log_level = _log_level;
                        }

                        template<typename ... Logs>
                                void logger(const int level, const char *fmt, Logs...logs)
                                {
                                        if (level >= log_level) {
                                                sd_journal_print(level, fmt, logs...);
                                        }
                                }
        };
}

#endif // _cf_logger_h_
