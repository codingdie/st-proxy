//
// Created by codingdie on 10/20/22.
//

#ifndef ST_PROXY_VIRTUAL_PORT_MANAGER_H
#define ST_PROXY_VIRTUAL_PORT_MANAGER_H

#include "st.h"
class virtual_port_manager {

public:
    static virtual_port_manager &uniq();

    std::pair<std::string, uint16_t> get_real_port(uint32_t ip, uint16_t port);

    uint16_t register_area_virtual_port(uint32_t ip, uint16_t port, const string &area);

private:
    std::unordered_map<string, pair<string, uint16_t>> virtual_port_map;

    static uint16_t get_virtual_port_begin();
    static string build_key(uint32_t ip, uint16_t port);
};


#endif//ST_PROXY_VIRTUAL_PORT_MANAGER_H
