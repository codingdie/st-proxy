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
    bool onlyAreaIp = false;
    vector<string> whitelist;
    set<uint32_t> whitelistIPs;
    int priority = 0;
    string toString();

    StreamTunnel(const string &type, const string &area, bool onlyAreaIp);

    StreamTunnel(const string &type, const string &ip, int port, const string &area,
                   bool onlyAreaIp);
};


#endif//ST_PROXY_StreamTunnel_H
