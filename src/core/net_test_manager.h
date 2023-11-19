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
#define multi_test_callback std::function<void()>

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
    void tls_handshake(uint32_t dist_ip, const net_test_callback &callback);
    void tls_handshake_with_socks(const std::string &socks_ip, uint32_t socks_port, const std::string &test_ip,
                                     const net_test_callback &callback);
    //http test 22 port
    void http_random(uint32_t dist_ip, const net_test_callback &callback);
    //random send package, receive response
    void random_package(uint32_t dist_ip, uint16_t port, const net_test_callback &callback);

private:

    const string TLS_REQUEST_BASE64 =
            "FgMBAgABAAH8AwP3ahaW4vzdplXY2naKY77SC+CkSDclrkS+yf4WO756iSABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAgmpoTARMCEwPAK8AvwCzAMMypzKjAE8AUAJwAnQAvADUBAAGTKioAAAAXAAAAIwCge3TRCqH+psnWX7Rq18kTwm4Mv/Loq6tjiG4JdvKzUh65PXw+8cGfLU4KGCzCW9CWaIjuoOgtFM4xuT+Sh5Q2NMonOBZ+dbBctLacexg5j8flq91Vn5SLniKPA3LgYwMx3MaDHwARUMQHdSIOIMx0LpDKz5rT1Xg9Gropq3kBge0dIz7N7aYKJhoGupYGm08y4q9Jwg0oIdUWE3a8Vix/H/8BAAEAAAoACgAIenoAHQAXABgALQACAQFEaQAFAAMCaDIADQASABAEAwgEBAEFAwgFBQEIBgYBABsAAwIAAgASAAAACwACAQAAAAASABAAAA13d3cuYmFpZHUuY29tACsABwbq6gMEAwMAEAAOAAwCaDIIaHR0cC8xLjEAMwArACl6egABAAAdACDvetaiYWqBPTT1A+CJ5vFNDb5g0pXUdjCa/zWsHl4JDAAFAAUBAAAAAPr6AAEAABUAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    void schedule_dispatch_test();
    void schedule_generate_key();
    void acquire_key(const std::function<void()> &callback);
    static const int TEST_REQUEST_LEN = 1024;
    const int TEST_TIME_OUT = 3000;
    static const int TEST_QPS = 30;
    static const int TEST_CONCURENT = 10;
    byte test_request[TEST_REQUEST_LEN]{};
    io_context ic;
    volatile double key_count = 0;
    volatile uint16_t running_test = 0;
    byte *tls_request;
    uint16_t tls_request_len;
    io_context::work *iw = nullptr;
    boost::asio::deadline_timer schedule_timer;
    boost::asio::deadline_timer generate_key_timer;
    std::unordered_map<string, test_case> test_queue;
    thread th;
    void do_test(stream_tunnel *tunnel, uint32_t dist_ip, uint16_t port, const net_test_callback &callback);
    void test_tunnel(stream_tunnel *tunnel, const test_case &tc, const multi_test_callback &callback);
    void test_all_tunnels(const vector<stream_tunnel *> &result, const test_case &tc,
                          const multi_test_callback &callback);
    test_case poll_one_test();
    void reset_tls_session_id();
};


#endif//ST_PROXY_NET_TEST_MANAGER_H
