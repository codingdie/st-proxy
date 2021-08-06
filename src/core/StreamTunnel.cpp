//
// Created by codingdie on 2020/10/8.
//

#include "StreamTunnel.h"

StreamTunnel::StreamTunnel(const string &type, const string &ip, int port, const string &area, bool onlyAreaIp)
    : type(type), ip(ip), port(port), area(area) {}

StreamTunnel::StreamTunnel(const string &type, const string &area) : type(type), area(area) {}

string StreamTunnel::toString() {
    if ("DIRECT" == type) {
        return "DIRECT";
    } else {
        return type + ":" + ip + ":" + to_string(port);
    }
}
