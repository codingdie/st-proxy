//
// Created by codingdie on 2020/10/5.
//

#include "SessionManager.h"
#include <mutex>

static mutex monitorLock;
static mutex statsLock;
Session *SessionManager::addNewSession(Session *session) {
    session->id = ++id;
    auto theId = session->id;
    Logger::traceId = theId;
    session->start();
    {
        lock_guard<mutex> lockGuard(statsLock);
        connections.emplace(make_pair(theId, session));
    };
    return session;
}

SessionManager::SessionManager()
    : id(0), randomRange(1024, 12000), ioContextWork(new boost::asio::io_context::work(ioContext)),
      timerTh([&] { ioContext.run(); }), statTimer(ioContext), sessionTimer(ioContext) {
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
    for (auto it = speeds.begin(); it != speeds.end(); it++) {
        auto down = it->second.first;
        auto up = it->second.second;
        if ((down.first > 0 && down.second > 0) || (up.first > 0 && up.second > 0)) {
            Logger::INFO << "tunnel" << it->first << "read" << to_string(down.second / 1024) + "KiB"
                         << "speed" << ((down.first > 0) ? down.second * 1.0 / down.first / 1024 * 1000 : 0) << "write"
                         << to_string(up.second / 1024) + "KiB"
                         << "speed" << ((up.first > 0) ? up.second * 1.0 / up.first / 1024 * 1000 : 0) << END;
        }
    }
    speeds.clear();
}

uint16_t SessionManager::guessUnusedSafePort() { return randomRange(randomEngine); }


void SessionManager::scheduleStats() {
    statTimer.expires_from_now(boost::posix_time::seconds(30));
    statTimer.async_wait([&](boost::system::error_code ec) {
        if (id > 0) {
            this->stats();
        }
        this->scheduleStats();
    });
}

void SessionManager::scheduleMonitor() {
    sessionTimer.expires_from_now(boost::posix_time::seconds(5));
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
    st::dns::SHM::read().relocateReadSHM();
    set<uint64_t> closedIds;
    {
        lock_guard<mutex> monitorLockGuard(monitorLock);
        lock_guard<mutex> statsLockGuard(statsLock);
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
                APMLogger::perf("st-proxy-stream", session->dimensions({{"direction", "down"}}), readInterval.second);
                APMLogger::perf("st-proxy-stream", session->dimensions({{"direction", "up"}}), writeInterval.second);
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
                Logger::ERROR << "session manager shutdown connect timeout session" << session->idStr() << END;
            } else if (!session->isTransmitting()) {
                session->shutdown();
                Logger::ERROR << "session manager shutdown noRead noWrite session" << session->idStr() << END;
            }
        }
    }
    for (auto it = closedIds.begin(); it != closedIds.end(); it++) {
        destroySession(*it);
    }
}
