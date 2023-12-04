//
// Created by codingdie on 10/16/22.
//
#include "net_test_manager.h"
#include <gtest/gtest.h>
TEST(proxy_unit_tests, test_tls_handshake_v2_with_socks) {
    mutex lock;
    lock.lock();
    net_test_manager::uniq().tls_handshake_with_socks("192.168.31.20", 10000, "18.65.168.167",
                                                      [=, &lock](bool valid, bool connected, uint32_t cost) {
                                                          logger::INFO << valid << connected << cost << END;
                                                          lock.unlock();
                                                      });
    lock.lock();
    lock.unlock();
}

TEST(proxy_unit_tests, test_ip) {
    st::utils::shell::exec("rm -rf /var/lib/st/kv/st-proxy-quality");
    st::proxy::config::uniq().load("../confs/test");

    quality_analyzer::uniq().delete_all_record();
    uint32_t distIp = st::utils::ipv4::str_to_ip("18.65.168.167");
    auto select_result = quality_analyzer::uniq().select_tunnels(distIp, {}, "");
    net_test_manager::uniq().test(distIp, 443, select_result);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    select_result = quality_analyzer::uniq().select_tunnels(distIp, {}, "");
    net_test_manager::uniq().test(distIp, 443, select_result);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    select_result = quality_analyzer::uniq().select_tunnels(distIp, {}, "");
    net_test_manager::uniq().test(distIp, 443, select_result);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    apm_logger::disable();
}

TEST(proxy_unit_tests, test_net_test_manager_test_with_socks) {
    st::proxy::config::uniq().load("../confs/test");
    auto tunnel = st::proxy::config::uniq().tunnels[1];
    net_test_manager::uniq().tls_handshake_with_socks(
            tunnel->ip, tunnel->port, "127.0.0.1",
            [=](bool valid, bool connected, uint32_t cost) { logger::INFO << valid << connected << cost << END; });
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
