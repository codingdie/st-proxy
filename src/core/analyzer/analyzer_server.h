//
// Created by codingdie on 24-4-12.
//

#ifndef ST_PROXY_ANALYZER_SERVER_H
#define ST_PROXY_ANALYZER_SERVER_H

#include "console/udp_console.h"
class analyzer_server {
public:
    analyzer_server();

    void start();

    void wait_start();

    void shutdown();

private:
   st::console::udp_console * console;
};


#endif//ST_PROXY_ANALYZER_SERVER_H
