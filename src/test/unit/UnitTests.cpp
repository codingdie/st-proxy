//
// Created by codingdie on 2020/6/27.
//
#include "ProxyServer.h"
#include <gtest/gtest.h>

// Demonstrate some basic assertions.
TEST(UnitTests, testDNSResolve) {
    ASSERT_STRNE(st::utils::ipv4::ipsToStr(st::utils::dns::query("114.114.114.114", "google.com")).c_str(), "");
    ASSERT_STRNE(st::utils::ipv4::ipsToStr(st::utils::dns::query("google.com")).c_str(), "");
    ASSERT_STREQ(st::utils::ipv4::ipsToStr(st::utils::dns::query("0.0.0.0", "google.com")).c_str(), "");
}