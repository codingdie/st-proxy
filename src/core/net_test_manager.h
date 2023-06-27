//
// Created by codingdie on 10/16/22.
//

#ifndef ST_PROXY_NET_TEST_MANAGER_H
#define ST_PROXY_NET_TEST_MANAGER_H

#include "common.h"
#include "quality_analyzer.h"
#include "socks5_utils.h"
#include <functional>
#define net_test_callback std::function<void(bool valid, bool connected, uint32_t cost)>

class test_case {
public:
    uint32_t ip;
    uint16_t port;
    uint16_t status;
    uint64_t timestamp;
    uint16_t priority = 0;
    test_case(uint32_t ip, uint16_t port);
    string key() const;
    bool operator<(const test_case &rhs) const;
};
class net_test_manager {
public:
    static net_test_manager &uniq();
    net_test_manager();
    virtual ~net_test_manager();
    void test(uint32_t dist_ip, uint16_t port, uint16_t priority);

    //https handshake test 443 port
    void tls_handshake_v2(uint32_t dist_ip, const net_test_callback &callback);
    void tls_handshake_v2_with_socks(const std::string &socks_ip, uint32_t socks_port, const std::string &test_ip,
                                     const net_test_callback &callback);
    //http test 22 port
    void http_random(uint32_t dist_ip, const net_test_callback &callback);
    //random send package, receive response
    void random_package(uint32_t dist_ip, uint16_t port, const net_test_callback &callback);

private:
    static const int TLS_REQUEST_LEN = 517;
    const char TLS_REQUEST[TLS_REQUEST_LEN + 1] =
            ".... . .....c..q...%........7.:....].)....0 ^4\". ...A ...D..R..es..U.P..>.`>  "
            ".........+./.,.0........ . . / 5. ..ZZ     . .  .000.000000.000 .  .. . ... . . . . ..  #   "
            ". .  .h2.http/1.1 . .. . ................. .   3 + ).. .  .  "
            ".`Z..^...8@e...>g..'.'...f.l.._B - ... + ........ . .. .Di . ..h2jj .  . .";
    void schedule_dispatch_test();
    void schedule_generate_key();
    void acquire_key(const std::function<void()> &callback);
    static const int TEST_REQUEST_LEN = 1024;
    static const int TEST_TIME_OUT = 3000;
    static const int TEST_QPS = 3;
    static const int TEST_CONCURENT = 3;
    byte test_request[TEST_REQUEST_LEN]{};
    io_context ic;
    volatile double key_count = 0;
    volatile uint16_t running_test = 0;

    io_context::work *iw = nullptr;
    boost::asio::deadline_timer schedule_timer;
    boost::asio::deadline_timer generate_key_timer;
    std::unordered_map<string, test_case> test_queue;
    thread th;
    void do_test(stream_tunnel *tunnel, uint32_t dist_ip, uint16_t port, const net_test_callback &callback);

    void test_re(select_tunnels_tesult result, uint32_t index, const test_case &tc, uint32_t valid_count,
                 const std::function<void(uint32_t valid)> &callback);
    test_case poll_one_test();
};


#endif//ST_PROXY_NET_TEST_MANAGER_H
