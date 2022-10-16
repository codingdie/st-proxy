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
    void add(proxy_session *session);

    uint16_t guess_unused_port();

    explicit session_manager(io_context *ic);


    virtual ~session_manager();

private:
    bool destroy(uint64_t sid);

    unordered_map<uint64_t, proxy_session *> connections;
    default_random_engine random_engine;
    uniform_int_distribution<unsigned short> random_range;//随机数分布对象
    boost::asio::deadline_timer session_timer;
    io_context *ic = nullptr;
    void schedule_monitor();
    void monitor_session();
};


#endif//ST_PROXY_SESSION_MANAGER_H
