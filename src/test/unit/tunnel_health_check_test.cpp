//
// Created by codingdie on 2026-05-29.
//
#include "analyzer/net_test_manager.h"
#include "config.h"
#include "stream_tunnel.h"
#include <gtest/gtest.h>

TEST(proxy_unit_tests, test_tunnel_health_status_transitions) {
    stream_tunnel t("DIRECT", "", 0);
    ASSERT_EQ(t.health_status.load(), HEALTH_UNKNOWN);
    ASSERT_FALSE(t.is_down());
    ASSERT_FALSE(t.is_up());

    t.health_status.store(HEALTH_UP);
    ASSERT_TRUE(t.is_up());
    ASSERT_FALSE(t.is_down());

    t.health_status.store(HEALTH_DOWN);
    ASSERT_TRUE(t.is_down());
    ASSERT_FALSE(t.is_up());
}

TEST(proxy_unit_tests, test_default_http_check_url_for_cn) {
    st::proxy::config::uniq().load("../confs/test");
    bool found_direct_or_cn = false;
    for (const auto *tunnel : st::proxy::config::uniq().tunnels) {
        if (tunnel->type == "DIRECT" || tunnel->area == "CN") {
            found_direct_or_cn = true;
            ASSERT_FALSE(tunnel->http_check_url.empty())
                    << "DIRECT/CN tunnel http_check_url should have default";
        } else {
            ASSERT_FALSE(tunnel->http_check_url.empty())
                    << "non-CN tunnel http_check_url should have default";
        }
    }
    ASSERT_TRUE(found_direct_or_cn);
}
