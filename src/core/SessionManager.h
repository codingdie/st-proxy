//
// Created by codingdie on 2020/10/5.
//

#ifndef ST_PROXY_SESSIONMANAGER_H
#define ST_PROXY_SESSIONMANAGER_H

#include "Common.h"
#include "Config.h"
#include "Session.h"
#include <random>
#include <unordered_map>
#include <unordered_set>

using std::default_random_engine;

using namespace std;

class SessionManager {
public:
    Session *addNewSession(tcp::socket &socket);

    bool destroySession(uint64_t id);
    void stats();

    uint16_t guessUnusedSafePort();

    SessionManager();

    static SessionManager *INSTANCE;

    virtual ~SessionManager();

private:
    unordered_map<uint64_t, Session *> connections;
    unordered_map<string, pair<pair<uint64_t, uint64_t>, pair<uint64_t, uint64_t>>> speeds;
    std::atomic<uint64_t> id;
    default_random_engine randomEngine;
    uniform_int_distribution<unsigned short> randomRange;//随机数分布对象
    boost::asio::io_context ioContext;
    boost::asio::io_context::work *ioContextWork;

    std::thread timerTh;
    boost::asio::deadline_timer statTimer;
    boost::asio::deadline_timer sessionTimer;
    st::utils::dns::DNSReverseSHM dnsReverseSHM;
    void scheduleStats();
    void scheduleMonitor();
    void monitorSession();
};


#endif//ST_PROXY_SESSIONMANAGER_H
