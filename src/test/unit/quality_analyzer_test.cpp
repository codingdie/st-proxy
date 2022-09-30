//
// Created by codingdie on 9/23/22.
//
#include "quality_analyzer.h"
#include <gtest/gtest.h>
TEST(unit_tests, test_quality_analyzer) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_record(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 9);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 90);
    quality_analyzer::uniq().record_first_package_failed(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 30);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 999);
    auto record = quality_analyzer::uniq().get_record(distIp, tunnel);
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 5);
    auto s_record = record.records((record.queue_size() - 1) % quality_analyzer::MAX_QUEUE_SIZE);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 999);
    s_record = record.records((record.queue_size() - 3) % quality_analyzer::MAX_QUEUE_SIZE);
    ASSERT_FALSE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 0);
    s_record = record.records((record.queue_size() - 4) % quality_analyzer::MAX_QUEUE_SIZE);
    ASSERT_TRUE(s_record.success());
    ASSERT_EQ(s_record.first_package_cost(), 90);
}
TEST(unit_tests, test_quality_analyzer_async) {
    auto ic = new boost::asio::io_context();
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    auto old_record = quality_analyzer::uniq().get_record(distIp, tunnel);
    quality_analyzer::uniq().set_io_context(ic);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 90);
    quality_analyzer::uniq().record_first_package_failed(distIp, tunnel);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 30);
    quality_analyzer::uniq().record_first_package_success(distIp, tunnel, 60);
    ic->run();
    delete ic;
    auto record = quality_analyzer::uniq().get_record(distIp, tunnel);
    ASSERT_EQ(record.queue_size() - old_record.queue_size(), 4);
}


TEST(unit_tests, test_quality_analyzer_speed) {
    auto tunnel = new stream_tunnel("SOCKS", "192.168.31.20", 1080);
    int distIp = 3;
    quality_analyzer::uniq().record_first_package_failed(distIp, tunnel);
    uint64_t begin = time::now();
    for (int i = 0; i < 100000; i++) {
        quality_analyzer::uniq().get_record(distIp, tunnel);
    }
    logger::INFO << "cost" << time::now() - begin << END;
}