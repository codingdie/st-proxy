//
// Created by codingdie on 10/16/22.
//

#ifndef ST_PROXY_NET_TEST_MANAGER_H
#define ST_PROXY_NET_TEST_MANAGER_H

#include "common.h"
#include "quality_analyzer.h"
#include "socks5_utils.h"
#include "taskquque/task_queue.h"
#include <functional>
#define net_test_callback std::function<void(bool valid, bool connected, uint32_t cost)>
class test_case {
public:
    uint32_t ip;
    uint16_t port;
    stream_tunnel *tunnel = nullptr;
    uint16_t tunnel_test_index;

    string key() const;
};
class net_test_manager {
public:
    static net_test_manager &uniq();
    net_test_manager();
    virtual ~net_test_manager();
    void test(uint32_t dist_ip, uint16_t port, const select_tunnels_tesult &stt);

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
            "FgMBAgABAAH8AwP3ahaW4vzdplXY2naKY77SC+CkSDclrkS+"
            "yf4WO756iSABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAgmpoTARMCEwPAK8AvwCzAMMypzKjAE8AUAJwAnQAvADUBAAGTKi"
            "oAAAAXAAAAIwCge3TRCqH+psnWX7Rq18kTwm4Mv/"
            "Loq6tjiG4JdvKzUh65PXw+8cGfLU4KGCzCW9CWaIjuoOgtFM4xuT+Sh5Q2NMonOBZ+"
            "dbBctLacexg5j8flq91Vn5SLniKPA3LgYwMx3MaDHwARUMQHdSIOIMx0LpDKz5rT1Xg9Gropq3kBge0dIz7N7aYKJhoGupYGm08y4q9Jwg"
            "0oIdUWE3a8Vix/H/"
            "8BAAEAAAoACgAIenoAHQAXABgALQACAQFEaQAFAAMCaDIADQASABAEAwgEBAEFAwgFBQEIBgYBABsAAwIAAgASAAAACwACAQAAAAASABAA"
            "AA13d3cuYmFpZHUuY29tACsABwbq6gMEAwMAEAAOAAwCaDIIaHR0cC8xLjEAMwArACl6egABAAAdACDvetaiYWqBPTT1A+"
            "CJ5vFNDb5g0pXUdjCa/"
            "zWsHl4JDAAFAAUBAAAAAPr6AAEAABUAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    static const int TEST_REQUEST_LEN = 1024;
    const int TEST_TIME_OUT = 3000;

    byte test_request[TEST_REQUEST_LEN]{};
    io_context ic;
    byte *tls_request;
    uint16_t tls_request_len;
    io_context::work *iw = nullptr;
    std::unordered_map<string, test_case> test_queue;
    thread th;
    st::task::queue<test_case> t_queue;
    void do_test(stream_tunnel *tunnel, uint32_t dist_ip, uint16_t port, const net_test_callback &callback);
    void reset_tls_session_id();
};


#endif//ST_PROXY_NET_TEST_MANAGER_H
