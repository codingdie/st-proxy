//
// Created by codingdie on 10/16/22.
//
#include "net_test_manager.h"
#include <gtest/gtest.h>
TEST(proxy_unit_tests, test_net_test_manager) {

    //    for (int i = 0; i < 10; i++) {
    //        mutex m;
    //        m.lock();
    //        net_test_manager::uniq().tls_handshake_cost(ipv4::str_to_ip("142.250.71.78"),
    //                                                    [&](bool valid, bool connected, uint32_t cost) {
    //                                                        logger::INFO << valid << connected << cost << END;
    //                                                        m.unlock();
    //                                                    });
    //        m.lock();
    //        m.unlock();
    //    }
    for (int i = 0; i < 10; i++) {
        mutex m;
        m.lock();
        net_test_manager::uniq().test(ipv4::str_to_ip("142.250.71.78"), 222,
                                      [&](bool valid, bool connected, uint32_t cost) {
                                          logger::INFO << valid << connected << cost << END;
                                          m.unlock();
                                      });
        m.lock();
        m.unlock();
    }
}
