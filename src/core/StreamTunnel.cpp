//
// Created by codingdie on 2020/10/8.
//

#include "StreamTunnel.h"

StreamTunnel::StreamTunnel(const string &type, const string &ip, int port, const string &area, bool onlyAreaIp)
    : type(type), ip(ip), port(port), area(area) {}

StreamTunnel::StreamTunnel(const string &type, const string &area) : type(type), area(area) {}

string StreamTunnel::toString() {
    if (type.compare("DIRECT") == 0) {
        return "DIRECT";
    } else {
        return type + ":" + ip + ":" + to_string(port);
    }
}

bool StreamTunnel::inWhitelist(const string &domain) {
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
bool StreamTunnel::inWhitelist(const uint32_t ip) { return whitelistIPs.find(ip) != whitelistIPs.end(); }