//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_StreamTunnel_H
#define ST_PROXY_StreamTunnel_H

#include <map>
#include <set>
#include <utility>
#include "utils/STUtils.h"

class StreamTunnel {
public:
    string type = "DIRECT";
    string ip = "";
    int port = 0;
    string area = "";
    set<string> whitelist;
    set<uint32_t> whitelistIPs;

    string toString();

    StreamTunnel(const string &type, const string &area);

    StreamTunnel(const string &type, const string &ip, int port, const string &area,
                   bool onlyAreaIp);

    bool inWhitelist(const string &domain);
    bool inWhitelist(const uint32_t ip);
};


#endif//ST_PROXY_StreamTunnel_H
