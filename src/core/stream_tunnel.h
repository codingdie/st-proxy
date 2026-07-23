//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_PROXY_StreamTunnel_H
#define ST_PROXY_StreamTunnel_H

#include "st.h"
#include <atomic>
#include <map>
#include <utility>
#include <vector>

enum tunnel_health_status {
    HEALTH_UNKNOWN = 0,
    HEALTH_UP = 1,
    HEALTH_DOWN = 2,
};

class stream_tunnel {
public:
    string type = "DIRECT";
    string ip;
    int port = 0;
    string area;
    vector<string> proxyAreas;
    set<string> whitelist;
    set<uint32_t> ip_whitelist;
    string http_check_url;

    // 健康检查相关
    std::atomic<tunnel_health_status> health_status{HEALTH_UNKNOWN};
    std::atomic<uint32_t> last_success_count{0};  // 最近一轮成功次数 (0-3)
    std::atomic<uint64_t> last_check_time{0};
    std::atomic<uint32_t> last_check_cost{0};

    string id() const;

    stream_tunnel(const string &type, const string &ip, int port);

    bool in_whitelist(const string &domain);
    bool in_whitelist(const vector<string> &domains);
    bool in_whitelist(uint32_t input_ip);

    bool is_down() const { return health_status.load() == HEALTH_DOWN; }
    bool is_up() const { return health_status.load() == HEALTH_UP; }
};


#endif//ST_PROXY_StreamTunnel_H
