//
// Created by codingdie on 2020/10/8.
//

#include "stream_tunnel.h"

stream_tunnel::stream_tunnel(const string &type, const string &ip, int port) : type(type), ip(ip), port(port) {}


string stream_tunnel::toString() {
    if (type.compare("DIRECT") == 0) {
        return "DIRECT";
    } else {
        return type + ":" + ip + ":" + to_string(port);
    }
}

bool stream_tunnel::inWhitelist(const string &domain) {
    if (whitelist.find(domain) != whitelist.end()) {
        return true;
    }
    for (auto str : whitelist) {
        if (str[0] == '*' && str[1] == '.') {
            auto rootDomain = str.substr(2, str.length() - 2);
            if (rootDomain.length() > 0) {
                if (domain.compare(rootDomain) == 0) {
                    return true;
                }
                if (domain.find("." + rootDomain) != string::npos) {
                    return true;
                }
            }
        }
    }
    return false;
}
bool stream_tunnel::inWhitelist(const uint32_t ip) { return whitelistIPs.find(ip) != whitelistIPs.end(); }