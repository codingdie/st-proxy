//
// Created by codingdie on 2020/10/5.
//

#include "SessionManager.h"
#include <mutex>

static mutex monitorLock;
static mutex statsLock;
Session *SessionManager::addNewSession(tcp::socket &socket, st::proxy::Config &config) {
    Session *tcpSession = new Session(++id, socket, config);
    auto theId = tcpSession->id;
    Logger::traceId = theId;
    {
        lock_guard<mutex> lockGuard(statsLock);
        connections.emplace(make_pair(theId, tcpSession));
    };
    tcpSession->start();
    return tcpSession;
}

SessionManager::SessionManager()
    : id(0), randomRange(1024, 12000), ioContextWork(new boost::asio::io_context::work(ioContext)), timerTh([&] { ioContext.run(); }),
      statTimer(ioContext), sessionTimer(ioContext) {
    randomEngine.seed(time::now());
    scheduleStats();
    scheduleMonitor();
}

SessionManager *SessionManager::INSTANCE = new SessionManager();


bool SessionManager::destroySession(uint64_t id) {
    lock_guard<mutex> lockGuard(monitorLock);
    auto iterator = connections.find(id);
    if (iterator != connections.end()) {
        Session *session = iterator->second;
        delete session;
        connections.erase(iterator);
        return true;
    }
    return false;
}

void SessionManager::stats() {
    Logger::traceId = 0;
    Logger::INFO << "total sessions size:" << connections.size() << END;
    lock_guard<mutex> statsLockGuard(statsLock);
    for (auto it = connections.begin(); it != connections.end(); it++) {
        Logger::DEBUG << "session" << it->second->idStr() << END;
    }
    for (auto it = speeds.begin(); it != speeds.end(); it++) {
        auto down = it->second.first;
        auto up = it->second.second;
        if (down.first != 0 || up.first != 0) {
            Logger::INFO << "tunnel" << it->first << "read speed:" << down.second * 1000.0 / down.first
                         << "write speed:" << up.second * 1000.0 / up.first << END;
        }
    }
}

uint16_t SessionManager::guessUnusedSafePort() { return randomRange(randomEngine); }


void SessionManager::scheduleStats() {
    statTimer.expires_from_now(boost::posix_time::seconds(10));
    statTimer.async_wait([&](boost::system::error_code ec) {
        if (id > 0) {
            this->stats();
        }
        this->scheduleStats();
    });
}

void SessionManager::scheduleMonitor() {
    sessionTimer.expires_from_now(boost::posix_time::seconds(1));
    sessionTimer.async_wait([&](boost::system::error_code ec) {
        if (id > 0) {
            this->monitorSession();
        }
        this->scheduleMonitor();
    });
}

SessionManager::~SessionManager() {
    delete ioContextWork;
    statTimer.cancel();
    sessionTimer.cancel();
    timerTh.join();
}

void SessionManager::monitorSession() {
    auto now = time::now();
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
                if (speeds.find(tunnelId) == speeds.end()) {
                    speeds[tunnelId] = {{0, 0}, {0, 0}};
                }
                auto readInterval = session->readTunnelCounter.interval();
                auto writeInterval = session->writeTunnelCounter.interval();
                if (readInterval.second > 0) {
                    speeds[tunnelId].first.first += readInterval.first;
                    speeds[tunnelId].first.second += readInterval.second;
                }
                if (writeInterval.second > 0) {
                    speeds[tunnelId].second.first += writeInterval.first;
                    speeds[tunnelId].second.second += writeInterval.second;
                }
            }
            Logger::traceId = session->id;
            if (session->isClosed()) {
                closedIds.emplace(id);
            } else if (session->isConnectTimeout()) {
                session->shutdown();
                Logger::ERROR << "session manager shutdown connect timeout session" << id << END;
            } else if (!session->isTransmitting()) {
                session->shutdown();
                Logger::ERROR << "session manager shutdown noRead noWrite session" << id << END;
            }
        }
    }
    for (auto it = closedIds.begin(); it != closedIds.end(); it++) {
        destroySession(*it);
    }
}
