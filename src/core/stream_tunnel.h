//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_StreamTunnel_H
#define ST_PROXY_StreamTunnel_H

#include "st.h"
#include <map>
#include <utility>
#include <vector>

class stream_tunnel {
public:
    string type = "DIRECT";
    string ip;
    int port = 0;
    string area;
    vector<string> proxyAreas;
    set<string> whitelist;
    set<uint32_t> ip_whitelist;
    string http_check_url;

    string id() const;

    stream_tunnel(const string &type, const string &ip, int port);

    bool in_whitelist(const string &domain);
    bool in_whitelist(const vector<string> &domains);
    bool in_whitelist(uint32_t input_ip);
};


#endif//ST_PROXY_StreamTunnel_H
