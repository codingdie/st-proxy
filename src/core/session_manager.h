//
// Created by codingdie on 2020/10/5.
//

#ifndef ST_PROXY_SESSION_MANAGER_H
#define ST_PROXY_SESSION_MANAGER_H

#include "common.h"
#include "config.h"
#include "proxy_session.h"
#include <random>
#include <unordered_map>
#include <unordered_set>

using std::default_random_engine;

using namespace std;

class session_manager {
public:
    proxy_session *add(proxy_session *session);

    bool destroy(uint64_t sid);


    uint16_t guess_unused_port();

    session_manager(io_context *ic);


    virtual ~session_manager();

private:
    unordered_map<uint64_t, proxy_session *> connections;
    unordered_map<string, pair<pair<uint64_t, uint64_t>, pair<uint64_t, uint64_t>>> speeds;
    std::atomic<uint64_t> id;
    default_random_engine random_engine;
    uniform_int_distribution<unsigned short> random_range;//随机数分布对象

    boost::asio::deadline_timer stats_timer;
    boost::asio::deadline_timer session_timer;
    void schedule_stats();
    void stats();

    void schedule_monitor();
    void monitor_session();
};


#endif//ST_PROXY_SESSION_MANAGER_H
