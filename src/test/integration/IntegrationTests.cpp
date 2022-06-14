//
// Created by codingdie on 2020/6/27.
//
#include "nat_utils.h"
#include "proxy_server.h"
#include <gtest/gtest.h>
class BaseTest : public ::testing::Test {
protected:
    proxy_server *proxyServer;
    thread *th;
    void SetUp() override {
        st::proxy::config::INSTANCE.load("../confs/test");
        proxyServer = new proxy_server();
        th = new thread([=]() { proxyServer->start(); });
        proxyServer->wait_start();
    }
    void TearDown() override {
        proxyServer->shutdown();
        th->join();
        delete th;
        delete proxyServer;
    }
};
class IntegrationTests : public BaseTest {
protected:
    void SetUp() override {
        BaseTest::SetUp();// Sets up the base fixture first.
    }
    void TearDown() override { BaseTest::TearDown(); }
};

TEST_F(IntegrationTests, testCURL) {
    nat_utils::INSTANCE.addTestDomain("www.google.com");
    string result;
    st::utils::shell::exec(
            "curl -s --location --connect-timeout 70 -m 70  --request GET https://www.google.com", result);
    ASSERT_TRUE(result.length()>0);
}
