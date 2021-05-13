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
        proxyServer = new ProxyServer(st::proxy::Config::INSTANCE);
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
    NATUtils::INSTANCE.addTestDomain("hanime.tv");
    string result;
    string get = "curl -s --location  --request GET https://hanime.tv/country_code";
    st::utils::shell::exec(get, result);
    ASSERT_STREQ(result.c_str(), "{\"country_code\":\"US\"}");
    st::utils::shell::exec(get, result);
    ASSERT_STREQ(result.c_str(), "{\"country_code\":\"US\"}");
    st::utils::shell::exec(get, result);
    ASSERT_STREQ(result.c_str(), "{\"country_code\":\"US\"}");
}
