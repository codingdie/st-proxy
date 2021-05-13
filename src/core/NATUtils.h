//
// Created by codingdie on 2020/10/5.
//

#ifndef ST_PROXY_NATUTILS_H
#define ST_PROXY_NATUTILS_H

#include "Common.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __APPLE__

#include <sys/ioctl.h>

#define PRIVATE

#include "net/pfvar.h"

#endif

#include <vector>

class NATUtils {
public:
    static NATUtils INSTANCE;

    NATUtils();

    tcp::endpoint getProxyAddr(tcp::socket &socket);

    bool addToWhitelist(uint32_t ips);
    
    bool addTestDomain(string domain);

    bool addToIPSet(string name, uint32_t ips);

    bool addToIPSet(string name, string domain);

private:
#ifdef __APPLE__
    int pffd = -1;

    tcp::endpoint getDstAddrForMac(__uint32_t clientIp, __uint16_t clientPort, __uint32_t serverIp, __uint16_t serverPort);

#endif
};


#endif//ST_PROXY_NATUTILS_H
