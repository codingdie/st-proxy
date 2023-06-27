//
// Created by codingdie on 10/16/22.
//
#include "net_test_manager.h"
#include <gtest/gtest.h>
TEST(proxy_unit_tests, test_net_test_manager) {
    // logger::LEVEL = 0;
    // st::proxy::config::uniq().load("../confs/test");
    // net_test_manager::uniq().test(ipv4::str_to_ip("142.250.204.36"), 443);
    // net_test_manager::uniq().test(ipv4::str_to_ip("172.64.195.32"), 443);
    // net_test_manager::uniq().test(ipv4::str_to_ip("172.64.194.32"), 443);
    // std::this_thread::sleep_for(std::chrono::seconds(300));
}

TEST(proxy_unit_tests, test_net_test_manager_test_with_socks) {
    st::proxy::config::uniq().load("../confs/test");
    auto tunnel = st::proxy::config::uniq().tunnels[1];
    net_test_manager::uniq().tls_handshake_v2_with_socks(
            tunnel->ip, tunnel->port, "127.0.0.1",
            [=](bool valid, bool connected, uint32_t cost) { logger::INFO << valid << connected << cost << END; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
