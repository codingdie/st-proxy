//
// Created by codingdie on 2020/10/8.
//

#include "stream_tunnel.h"

stream_tunnel::stream_tunnel(const string &type, const string &ip, int port) : type(type), ip(ip), port(port) {}


string stream_tunnel::id() const {
    if (type == "DIRECT") {
        return "DIRECT";
    } else {
        return type + ":" + ip + ":" + to_string(port);
    }
}

bool stream_tunnel::in_whitelist(const string &domain) {
    if (whitelist.find(domain) != whitelist.end()) {
        return true;
    }
    for (auto str : whitelist) {
        if (str[0] == '*' && str[1] == '.') {
            auto rootDomain = str.substr(2, str.length() - 2);
            if (rootDomain.length() > 0) {
                if (domain == rootDomain) {
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
bool stream_tunnel::in_whitelist(uint32_t input_ip) { return ip_whitelist.find(input_ip) != ip_whitelist.end(); }
bool stream_tunnel::in_whitelist(const vector<string> &domains) {
    for (const auto &domain : domains) {
        if (in_whitelist(domain)) {
            return true;
        }
    }
    return false;
}
