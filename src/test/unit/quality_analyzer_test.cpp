//
// Created by codingdie on 9/23/22.
//
#include "quality_analyzer.h"
#include "st.h"
#include <gtest/gtest.h>
TEST(proxy_unit_tests, test_quality_analyzer_forbid) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int dist_ip = 3;
    auto old_record = quality_analyzer::uniq().get_record(dist_ip, tunnel);
    for (auto i = 0; i < quality_analyzer::IP_TEST_COUNT + 1; i++) {
        quality_analyzer::uniq().record_failed(dist_ip, tunnel);
    }

    ASSERT_TRUE(st::proxy::shm::uniq().is_ip_forbid(dist_ip));
    quality_analyzer::uniq().record_first_package_success(dist_ip, tunnel, 30, false);
    ASSERT_FALSE(st::proxy::shm::uniq().is_ip_forbid(dist_ip));
    delete tunnel;
}

TEST(proxy_unit_tests, test_quality_analyzer) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_record(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 9, false);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 90, false);
    quality_analyzer::uniq().record_failed(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 30, false);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 999, false);
    auto record = quality_analyzer::uniq().get_record(distIp, tunnel);
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 5);
    auto s_record = record.records((record.queue_size() - 1) % TUNNEL_TEST_COUNT);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 999);
    s_record = record.records((record.queue_size() - 2) % TUNNEL_TEST_COUNT);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 30);
    s_record = record.records((record.queue_size() - 3) % TUNNEL_TEST_COUNT);
    ASSERT_FALSE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 0);
    delete tunnel;
}

TEST(proxy_unit_tests, test_quality_analyzer_async) {
    auto ic = new boost::asio::io_context();
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_record(distIp, tunnel);
    quality_analyzer::uniq().set_io_context(ic);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 90, false);
    quality_analyzer::uniq().record_failed(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 30, false);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 60, false);
    ic->run();
    delete ic;
    auto record = quality_analyzer::uniq().get_record(distIp, tunnel);
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 4);
    delete tunnel;
}


TEST(proxy_unit_tests, test_quality_analyzer_speed) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    quality_analyzer::uniq().record_failed(distIp, tunnel);
    uint64_t begin = time::now();
    for (int i = 0; i < 100000; i++) {
        quality_analyzer::uniq().get_record(distIp, tunnel);
    }
    logger::INFO << "cost" << time::now() - begin << END;
    delete tunnel;
}