//
// Created by codingdie on 10/20/22.
//

#include "virtual_port_manager.h"
#include "nat_utils.h"
uint16_t virtual_port_manager::get_virtual_port_begin() {
    uint16_t virtual_port_begin = 60000;
    const char *env = getenv("ST_PROXY_VIRTUAL_PORT_BEGIN");
    string virtual_port_begin_str;
    if (env != nullptr) {
        virtual_port_begin_str = env;
        if (virtual_port_begin_str.length() > 0) {
            virtual_port_begin = stoul(virtual_port_begin_str);
        }
    }
    return virtual_port_begin;
}

std::pair<std::string, uint16_t> virtual_port_manager::get_real_port(uint32_t ip, uint16_t port) {
    auto key = build_key(ip, port);
    if (virtual_port_map.find(key) != virtual_port_map.end()) {
        return virtual_port_map.at(key);
    }

    return make_pair("", port);
}
string virtual_port_manager::build_key(uint32_t ip, uint16_t port) {
    return ipv4::ip_to_str(ip) + ":" + to_string(port);
}
virtual_port_manager &virtual_port_manager::uniq() {
    static virtual_port_manager vp;
    return vp;
}
uint16_t virtual_port_manager::register_area_virtual_port(uint32_t ip, uint16_t port, const string &area) {
    auto issued_port = get_virtual_port_begin();
    for (const auto &item : virtual_port_map) {
        auto splits = strutils::split(item.first, ":");
        auto o_port = (uint16_t) std::stoul(splits[1]);
        auto o_ip = utils::ipv4::str_to_ip(splits[0]);
        if (o_ip == ip) {
            if (item.second.first == area && item.second.second == port) {
                nat_utils::INSTANCE.add_proxy_ip(ip);
                return o_port;
            } else {
                issued_port = max(issued_port, o_port);
            }
        }
    }
    issued_port++;
    virtual_port_map.emplace(build_key(ip, issued_port), make_pair(area, port));
    return issued_port;
}
