//
// Created by codingdie on 9/23/22.
//
#include "virtual_port_manager.h"
#include <gtest/gtest.h>

TEST(proxy_unit_tests, test_virtual_port) {
    uint16_t v1 = virtual_port_manager::uniq().register_area_virtual_port((uint16_t) 123, (uint16_t) 123, "CN");
    uint16_t v2 = virtual_port_manager::uniq().register_area_virtual_port((uint16_t) 123, (uint16_t) 123, "CN");
    ASSERT_EQ(v1, v2);
}