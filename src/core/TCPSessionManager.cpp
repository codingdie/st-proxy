//
// Created by codingdie on 2020/10/5.
//

#include "TCPSessionManager.h"
#include <mutex>

static mutex monitorLock;
static mutex statsLock;
TCPSession *TCPSessionManager::addNewSession(tcp::socket &socket, st::proxy::Config &config) {
    TCPSession *tcpSession = new TCPSession(++id, socket, config);
    auto theId = tcpSession->id;
    Logger::traceId = theId;
    {
        lock_guard<mutex> lockGuard(statsLock);
        connections.emplace(make_pair(theId, tcpSession));
    };
    tcpSession->start();
    return tcpSession;
}

TCPSessionManager::TCPSessionManager()
    : id(0), randomRange(1024, 12000), ioContextWork(new boost::asio::io_context::work(ioContext)),
      timerTh([&] { ioContext.run(); }), statTimer(ioContext), sessionTimer(ioContext) {
    randomEngine.seed(time::now());
    scheduleStats();
    scheduleMonitor();
}

TCPSessionManager *TCPSessionManager::INSTANCE = new TCPSessionManager();


bool TCPSessionManager::destroySession(uint64_t id) {
    lock_guard<mutex> lockGuard(monitorLock);
    auto iterator = connections.find(id);
    if (iterator != connections.end()) {
        TCPSession *session = iterator->second;
        delete session;
        connections.erase(iterator);
        return true;
    }
    return false;
}

void TCPSessionManager::stats() {
    Logger::INFO << "total sessions:" << connections.size() << END;
    lock_guard<mutex> statsLockGuard(statsLock);
    for (auto it = speeds.begin(); it != speeds.end(); it++) {
        Logger::traceId = 0;
        double speed = 0;
        if (it->second.first != 0) { speed = it->second.second * 1.0 / it->second.first; }
        Logger::INFO << "tunnel" << it->first << "speed" << speed << END;
    }
}

uint16_t TCPSessionManager::guessUnusedSafePort() { return randomRange(randomEngine); }


void TCPSessionManager::scheduleStats() {
    statTimer.expires_from_now(boost::posix_time::seconds(5));
    statTimer.async_wait([&](boost::system::error_code ec) {
        if (id > 0) { this->stats(); }
        this->scheduleStats();
    });
}

void TCPSessionManager::scheduleMonitor() {
    sessionTimer.expires_from_now(boost::posix_time::seconds(1));
    sessionTimer.async_wait([&](boost::system::error_code ec) {
        if (id > 0) { this->monitorSession(); }
        this->scheduleMonitor();
    });
}

TCPSessionManager::~TCPSessionManager() {
    delete ioContextWork;
    statTimer.cancel();
    sessionTimer.cancel();
    timerTh.join();
}

void TCPSessionManager::monitorSession() {
    auto now = time::now();
    uint64_t soTimeout = st::proxy::Config::INSTANCE.soTimeout;
    uint64_t conTimeout = st::proxy::Config::INSTANCE.soTimeout;
    set<uint64_t> closedIds;
    {
        lock_guard<mutex> monitorLockGuard(monitorLock);
        lock_guard<mutex> statsLockGuard(statsLock);
        speeds.clear();
        for (auto it = connections.begin(); it != connections.end(); it++) {
            auto session = (*it).second;
            auto id = (*it).first;
            Logger::traceId = session->id;
            if (session->connectedTunnel != nullptr) {
                auto tunnelId = session->connectedTunnel->toString();
                if (speeds.find(tunnelId) == speeds.end()) { speeds[tunnelId] = {0, 0}; }
                speeds[tunnelId].first += session->readTunnelTime;
                speeds[tunnelId].second += session->readTunnelSize + session->writeTunnelSize;
            }
            bool noRead = session->lastReadTunnelTime == 0
                                  ? (now - session->begin >= soTimeout)
                                  : (now - session->lastReadTunnelTime >= soTimeout);
            bool noWrite = session->lastWriteTunnelTime == 0
                                   ? (now - session->begin >= soTimeout)
                                   : (now - session->lastWriteTunnelTime >= soTimeout);
            bool connectTimeout = session->stage == TCPSession::STAGE::CONNECTING
                                          ? (now - session->begin >= conTimeout)
                                          : false;
            bool closed = session->stage == TCPSession::STAGE::DETROYED;
            Logger::traceId = session->id;
            if (closed) {
                closedIds.emplace(id);
            } else if (connectTimeout) {
                session->shutdown();
                Logger::ERROR << "session manager shutdown connect timeout session" << id << END;
            } else if (noRead && noWrite) {
                session->shutdown();
                Logger::ERROR << "session manager shutdown noRead noWrite session" << id << END;
            }
        }
    }
    for (auto it = closedIds.begin(); it != closedIds.end(); it++) { destroySession(*it); }
}
