//
// Created by codingdie on 2020/6/27.
//
#include "NATUtils.h"
#include "ProxyServer.h"
#include <gtest/gtest.h>
class BaseTest : public ::testing::Test {
protected:
    ProxyServer *proxyServer;
    thread *th;
    void SetUp() override {
        st::proxy::Config::INSTANCE.load("../confs/test");
        proxyServer = new ProxyServer();
        th = new thread([=]() { proxyServer->start(); });
        proxyServer->waitStart();
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
    NATUtils::INSTANCE.addTestDomain("www.google.com");
    string result;
    st::utils::shell::exec(
            "curl -s --location --connect-timeout 70 -m 70  --request GET https://www.google.com", result);
    ASSERT_TRUE(result.length()>0);
}
