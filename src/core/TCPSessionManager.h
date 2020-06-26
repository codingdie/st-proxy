//
// Created by codingdie on 2020/10/5.
//

#ifndef ST_PROXY_TCPSESSIONMANAGER_H
#define ST_PROXY_TCPSESSIONMANAGER_H

#include "Common.h"
#include "Config.h"
#include "TCPSession.h"
#include <random>
#include <unordered_map>
#include <unordered_set>
using std::default_random_engine;

using namespace std;

class TCPSessionManager {
public:
    TCPSession *addNewSession(tcp::socket &socket, st::proxy::Config &config);

    bool destroySession(uint64_t id);
    void stats();

    uint16_t guessUnusedSafePort();

    TCPSessionManager();

    static TCPSessionManager *INSTANCE;

    virtual ~TCPSessionManager();

private:
    unordered_map<uint64_t, TCPSession *> connections;
    unordered_map<string, pair<uint64_t, uint64_t>> speeds;
    std::atomic<uint64_t> id;
    default_random_engine randomEngine;
    uniform_int_distribution<unsigned short> randomRange;//随机数分布对象
    boost::asio::io_context ioContext;
    boost::asio::io_context::work *ioContextWork;

    std::thread timerTh;
    boost::asio::deadline_timer statTimer;
    boost::asio::deadline_timer sessionTimer;

    void scheduleStats();
    void scheduleMonitor();
    void monitorSession();
};


#endif//ST_PROXY_TCPSESSIONMANAGER_H
