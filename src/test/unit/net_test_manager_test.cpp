//
// Created by codingdie on 10/16/22.
//
#include "net_test_manager.h"
#include <gtest/gtest.h>
TEST(proxy_unit_tests, test_tls_handshake_v2_with_socks) {
    mutex lock;
    lock.lock();
    net_test_manager::uniq().tls_handshake_with_socks("192.168.31.20", 10020, "142.250.204.68",
                                                      [=, &lock](bool valid, bool connected, uint32_t cost) {
                                                          logger::INFO << valid << connected << cost << END;
                                                          lock.unlock();
                                                      });
    lock.lock();
    lock.unlock();
}

TEST(proxy_unit_tests, test_net_test_manager_test_with_socks) {
    st::proxy::config::uniq().load("../confs/test");
    auto tunnel = st::proxy::config::uniq().tunnels[1];
    net_test_manager::uniq().tls_handshake_with_socks(
            tunnel->ip, tunnel->port, "127.0.0.1",
            [=](bool valid, bool connected, uint32_t cost) { logger::INFO << valid << connected << cost << END; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
