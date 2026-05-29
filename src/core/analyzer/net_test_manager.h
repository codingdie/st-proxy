//
// Created by codingdie on 10/16/22.
//

#ifndef ST_PROXY_NET_TEST_MANAGER_H
#define ST_PROXY_NET_TEST_MANAGER_H

#include "analyzer/quality_analyzer.h"
#include "common.h"
#include "socks5_utils.h"
#include "taskquque/task_queue.h"
#include <functional>
#define net_test_callback std::function<void(bool valid, bool connected, uint32_t cost)>
#define select_tunnels_tesult vector<pair<stream_tunnel *, pair<int, proxy::proto::quality_record>>>
class socks5_proxy {
public:
    string ip;
    uint16_t port;
};
class test_case {
public:
    uint32_t ip;
    uint16_t port;
    socks5_proxy proxy;
    uint16_t tunnel_test_index;
    string tunnel_id;
    string key() const;
};
class net_test_manager {
public:
    static net_test_manager &uniq();
    net_test_manager();
    virtual ~net_test_manager();
    void submit(const st::task::priority_task<test_case> &t);

    //https handshake test 443 port
    void tls_handshake(uint32_t dist_ip, const net_test_callback &callback);
    void tls_handshake_with_socks(const std::string &socks_ip, uint32_t socks_port, const std::string &test_ip,
                                  const net_test_callback &callback);
    vector<task::priority_task<test_case>> current_all_test();

    // 启动隧道健康检查定时器（30 秒一轮）
    void start_tunnel_health_check();

    // 对单个隧道做一次健康检查
    void check_tunnel_health(stream_tunnel *tunnel,
                             const std::function<void(bool, uint32_t)> &callback);

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

    byte test_request[TEST_REQUEST_LEN]{};
    io_context ic;
    byte *tls_request;
    uint16_t tls_request_len;
    io_context::work *iw = nullptr;
    thread th;
    st::task::queue<test_case> t_queue;
    void do_test(socks5_proxy proxy, uint32_t dist_ip, uint16_t port, const net_test_callback &callback);
    void reset_tls_session_id();

    static constexpr uint32_t TUNNEL_HEALTH_CHECK_INTERVAL_MS = 30000;
    static constexpr uint32_t TUNNEL_HEALTH_CHECK_TIMEOUT_MS = 5000;
    static constexpr uint32_t TUNNEL_HEALTH_DOWN_THRESHOLD = 2;
    boost::asio::deadline_timer *health_check_timer = nullptr;
    void schedule_health_check();
    void run_health_check_round();
    static std::pair<std::string, uint16_t> parse_check_url(const std::string &url);
};


#endif//ST_PROXY_NET_TEST_MANAGER_H
