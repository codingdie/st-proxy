//
// Created by codingdie on 10/16/22.
//

#ifndef ST_PROXY_NET_TEST_MANAGER_H
#define ST_PROXY_NET_TEST_MANAGER_H

#include "common.h"
#include <functional>
#define net_test_callback std::function<void(bool valid, bool connected, uint32_t cost)>

class net_test_manager {
public:
    static net_test_manager &uniq();
    net_test_manager();
    virtual ~net_test_manager();
    void test(uint32_t dist_ip, uint16_t port, uint16_t count);

    void test(uint32_t dist_ip, uint16_t port, const net_test_callback &callback);

    //https handshake test 443 port
    void tls_handshake(uint32_t dist_ip, const net_test_callback &callback);
    //http test 22 port
    void http_random(uint32_t dist_ip, const net_test_callback &callback);
    //random send package, receive response
    void random_package(uint32_t dist_ip, uint16_t port, const net_test_callback &callback);

private:
    static const int TEST_REQUEST_LEN = 1024;
    static const int TEST_TIME_OUT = 3000;
    byte test_request[TEST_REQUEST_LEN]{};
    io_context ic;
    io_context::work *iw = nullptr;
    std::unordered_set<uint32_t> in_test_ips;
    thread th;
    mutex mt;
    void test_re(uint32_t dist_ip, uint16_t port, uint16_t count, const net_test_callback &callback);
};


#endif//ST_PROXY_NET_TEST_MANAGER_H
