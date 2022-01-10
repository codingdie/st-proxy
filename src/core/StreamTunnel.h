//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_StreamTunnel_H
#define ST_PROXY_StreamTunnel_H

#include "utils/STUtils.h"
#include <map>
#include <vector>
#include <utility>

class StreamTunnel {
public:
    string type = "DIRECT";
    string ip = "";
    int port = 0;
    vector<string> areas;
    set<string> whitelist;
    set<uint32_t> whitelistIPs;

    string toString();

    StreamTunnel(const string &type, const string &ip, int port);

    bool inWhitelist(const string &domain);
    bool inWhitelist(const uint32_t ip);
};


#endif//ST_PROXY_StreamTunnel_H
