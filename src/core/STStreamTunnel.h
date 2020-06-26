//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_STSTREAMTUNNEL_H
#define ST_PROXY_STSTREAMTUNNEL_H

#include <map>
#include <set>
#include <utility>
#include <utils/STUtils.h>

class STStreamTunnel {
public:
    string type = "DIRECT";
    string ip = "";
    int port = 0;
    string area = "";
    bool onlyAreaIp = false;
    string realServerHost = "";
    set<uint32_t> realServerIPs;
    vector<string> whitelistHosts;
    set<uint32_t> whitelistIPs;
    int priority = 0;
    string toString();

    STStreamTunnel(const string &type, const string &area, bool onlyAreaIp);

    STStreamTunnel(const string &type, const string &ip, int port, const string &area,
                   bool onlyAreaIp);
};


#endif//ST_PROXY_STSTREAMTUNNEL_H
