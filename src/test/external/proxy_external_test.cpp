#include "config.h"
#include "nat_utils.h"
#include "proxy_server.h"
#include <boost/process.hpp>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <thread>

class external_proxy_test : public ::testing::Test {
protected:
    void SetUp() override {
        st::proxy::config::uniq().load("../confs/test");
        proxy.reset(new proxy_server());
        proxy_thread = std::thread([this]() { proxy->start(); });
        proxy->wait_start();
    }

    void TearDown() override {
        if (proxy) {
            proxy->shutdown();
        }
        if (proxy_thread.joinable()) {
            proxy_thread.join();
        }
        st::proxy::config::uniq().unload();
    }

    std::unique_ptr<proxy_server> proxy;
    std::thread proxy_thread;
};

TEST_F(external_proxy_test, reaches_google_through_configured_socks_tunnel) {
    ASSERT_TRUE(nat_utils::uniq().add_test_domain("www.google.com"));

    boost::process::ipstream output;
    boost::process::ipstream error;
    boost::process::child curl("curl",
                               boost::process::args({"-s", "--location", "--connect-timeout", "5", "--max-time", "10",
                                                     "https://www.google.com"}),
                               boost::process::std_out > output, boost::process::std_err > error);
    if (!curl.wait_for(std::chrono::seconds(15))) {
        curl.terminate();
        curl.wait();
        FAIL() << "external SOCKS tunnel did not return within 15 seconds";
    }

    std::ostringstream response;
    response << output.rdbuf();
    std::ostringstream error_output;
    error_output << error.rdbuf();
    ASSERT_EQ(0, curl.exit_code()) << error_output.str();
    ASSERT_FALSE(response.str().empty());
}
