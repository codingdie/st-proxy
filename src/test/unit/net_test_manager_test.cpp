//
// Created by codingdie on 10/16/22.
//
#include "analyzer/net_test_manager.h"
#include <gtest/gtest.h>
#include <condition_variable>
#include <mutex>

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
    auto select_result = quality_analyzer::uniq().select_tunnels(distIp, 443, {}, "");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    select_result = quality_analyzer::uniq().select_tunnels(distIp, 443, {}, "");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    select_result = quality_analyzer::uniq().select_tunnels(distIp, 443, {}, "");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    apm_logger::disable();
}

TEST(proxy_unit_tests, test_net_test_manager_test_with_socks) {
    st::proxy::config::uniq().load("../confs/test");
    auto tunnel = st::proxy::config::uniq().tunnels[1];
    std::mutex mutex;
    std::condition_variable cv;
    bool finished = false;
    bool connected = true;

    net_test_manager::uniq().tls_handshake_with_socks(
            tunnel->ip, tunnel->port, "127.0.0.1", [&](bool valid, bool is_connected, uint32_t cost) {
                logger::INFO << valid << is_connected << cost << END;
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    connected = is_connected;
                    finished = true;
                }
                cv.notify_one();
            });

    std::unique_lock<std::mutex> lock(mutex);
    ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(3), [&]() { return finished; }));
    ASSERT_FALSE(connected);
}
