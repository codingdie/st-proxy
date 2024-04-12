//
// Created by codingdie on 24-4-12.
//

#ifndef ST_PROXY_PROXY_CONSOLE_H
#define ST_PROXY_PROXY_CONSOLE_H
#include "console/udp_console.h"


class proxy_console {
public:
    proxy_console();

    virtual ~proxy_console();
    void start();

    void shutdown();

private:
    st::console::udp_console *console;

    string analyse_ip(uint32_t ip);

    string analyse_ip_tunnels(uint32_t ip);

    string analyse_tunnel();
};


#endif//ST_PROXY_PROXY_CONSOLE_H
