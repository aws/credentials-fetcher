#include <cstdio>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#ifndef _daemon_h_
#define _daemon_h_

class Daemon {
    /* TBD:: Fill this later */

    public:
        uint64_t watchdog_interval_usecs = 0;
};

#endif // _daemon_h_
