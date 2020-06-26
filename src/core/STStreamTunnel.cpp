//
// Created by codingdie on 2020/10/8.
//

#include "STStreamTunnel.h"

STStreamTunnel::STStreamTunnel(const string &type, const string &ip, int port, const string &area, bool onlyAreaIp) : type(type), ip(ip), port(
        port), area(area), onlyAreaIp(onlyAreaIp) {
}

STStreamTunnel::STStreamTunnel(const string &type, const string &area, bool onlyAreaIp) : type(type), area(area), onlyAreaIp(
        onlyAreaIp) {
}

string STStreamTunnel::toString() {
    if (type == "DIRECT") {
        return "DIRECT";
    } else {
        return type + ": " + ip + ":" + to_string(port);
    }
}
