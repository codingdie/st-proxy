//
// Created by codingdie on 9/23/22.
//
#include "analyzer/quality_analyzer.h"
#include "config.h"
#include "st.h"
#include "utils/shm/proxy_shm.h"
#include <gtest/gtest.h>
#include <sstream>
//TEST(proxy_unit_tests, test_quality_analyzer_forbid) {
//    st::proxy::config::uniq().load("../confs/test");
//    auto tunnel = st::proxy::config::uniq().tunnels[1];
//    int dist_ip = 3;
//    auto old_record = quality_analyzer::uniq().get_tunnel_record(dist_ip, tunnel);
//    for (auto i = 0; i < st::proxy::config::uniq().tunnels.size(); i++) {
//        quality_analyzer::uniq().record_failed(dist_ip, tunnel);
//    }
//
//    ASSERT_TRUE(st::proxy::shm::uniq().is_ip_forbid(dist_ip));
//    quality_analyzer::uniq().record_first_package_success(dist_ip, tunnel, 30);
//    ASSERT_FALSE(st::proxy::shm::uniq().is_ip_forbid(dist_ip));
//}

TEST(proxy_unit_tests, test_quality_analyzer) {
    st::proxy::config::uniq().load("../confs/test");
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_ip_tunnel_record(distIp, tunnel->id());
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 9);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 90);
    quality_analyzer::uniq().record_failed(distIp, tunnel->id());
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 30);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 999);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto record = quality_analyzer::uniq().get_ip_tunnel_record(distIp, tunnel->id());
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 5);
    auto s_record = record.records((record.queue_size() - 1) % quality_analyzer::IP_TUNNEL_TEST_COUNT);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 999);
    s_record = record.records((record.queue_size() - 2) % quality_analyzer::IP_TUNNEL_TEST_COUNT);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 30);
    s_record = record.records((record.queue_size() - 3) % quality_analyzer::IP_TUNNEL_TEST_COUNT);
    ASSERT_FALSE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 0);
    delete tunnel;
}

TEST(proxy_unit_tests, test_quality_analyzer_async) {
    quality_analyzer::uniq().clear();
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_ip_tunnel_record(distIp, tunnel->id());
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 90);
    quality_analyzer::uniq().record_failed(distIp, tunnel->id());
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 30);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel->id(), 60);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto record = quality_analyzer::uniq().get_ip_tunnel_record(distIp, tunnel->id());
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 4);
    delete tunnel;
}

TEST(proxy_unit_tests, test_blacklist_expire_uses_minutes) {
    const uint32_t distIp = st::utils::ipv4::str_to_ip("203.0.113.10");
    quality_analyzer::uniq().remove_from_blacklist(distIp);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    quality_analyzer::uniq().add_to_blacklist(distIp);
    std::this_thread::sleep_for(std::chrono::seconds(11));

    ASSERT_TRUE(quality_analyzer::uniq().is_in_blacklist(distIp));
    quality_analyzer::uniq().remove_from_blacklist(distIp);
}

TEST(proxy_unit_tests, remove_missing_blacklist_ip_does_not_log_removed) {
    const uint32_t distIp = st::utils::ipv4::str_to_ip("203.0.113.250");

    std::ostringstream output;
    auto *old_buf = std::cout.rdbuf(output.rdbuf());
    quality_analyzer::uniq().remove_from_blacklist(distIp);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout.rdbuf(old_buf);

    ASSERT_EQ(output.str().find("removed from blacklist"), std::string::npos);
}


TEST(proxy_unit_tests, test_quality_analyzer_speed) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    quality_analyzer::uniq().record_failed(distIp, tunnel->id());
    uint64_t begin = time::now();
    for (int i = 0; i < 100000; i++) {
        quality_analyzer::uniq().get_ip_tunnel_record(distIp, tunnel->id());
    }
    logger::INFO << "cost" << time::now() - begin << END;
    delete tunnel;
}
