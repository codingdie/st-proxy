//
// Created by codingdie on 9/23/22.
//
#include "virtual_port_manager.h"
#include <gtest/gtest.h>

TEST(proxy_unit_tests, test_virtual_port) {
    uint16_t v1 = virtual_port_manager::uniq().register_area_virtual_port((uint16_t) 123, (uint16_t) 1234, "CN");
    uint16_t v2 = virtual_port_manager::uniq().register_area_virtual_port((uint16_t) 123, (uint16_t) 1234, "CN");
    ASSERT_EQ(v1, v2);
    auto r = virtual_port_manager::uniq().get_real_port((uint16_t) 123, v2);
    ASSERT_EQ("CN", r.first);
    ASSERT_EQ(1234, r.second);
}