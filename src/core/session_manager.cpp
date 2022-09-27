//
// Created by codingdie on 2020/10/5.
//

#include "session_manager.h"
#include <mutex>

static mutex monitorLock;
static mutex statsLock;
proxy_session *session_manager::add(proxy_session *session) {
    auto theId = session->id;
    logger::traceId = theId;
    session->start();
    {
        lock_guard<mutex> lg(statsLock);
        connections.emplace(make_pair(theId, session));
    }
    return session;
}

session_manager::session_manager(io_context *ic)
    : random_engine(time::now()), random_range(1024, 12000), stats_timer(*ic), session_timer(*ic) {
    schedule_stats();
    schedule_monitor();
}


bool session_manager::destroy(uint64_t sid) {
    lock_guard<mutex> lockGuard(monitorLock);
    auto iterator = connections.find(sid);
    if (iterator != connections.end()) {
        proxy_session *session = iterator->second;
        delete session;
        connections.erase(iterator);
        return true;
    }
    return false;
}

void session_manager::stats() {
    logger::traceId = 0;
    logger::INFO << "total sessions size:" << connections.size() << END;
    lock_guard<mutex> statsLockGuard(statsLock);
    for (auto &speed : speeds) {
        auto down = speed.second.first;
        auto up = speed.second.second;
        if ((down.first > 0 && down.second > 0) || (up.first > 0 && up.second > 0)) {
            logger::INFO << "tunnel" << speed.first << "read" << to_string(down.second / 1024) + "KiB"
                         << "speed" << ((down.first > 0) ? down.second * 1.0 / down.first / 1024 * 1000 : 0) << "write"
                         << to_string(up.second / 1024) + "KiB"
                         << "speed" << ((up.first > 0) ? up.second * 1.0 / up.first / 1024 * 1000 : 0) << END;
        }
    }
    speeds.clear();
}
uint16_t session_manager::guess_unused_port() { return random_range(random_engine); }

void session_manager::schedule_stats() {
    stats_timer.expires_from_now(boost::posix_time::seconds(30));
    stats_timer.async_wait([&](boost::system::error_code ec) {
        this->stats();
        this->schedule_stats();
    });
}

void session_manager::schedule_monitor() {
    session_timer.expires_from_now(boost::posix_time::seconds(5));
    session_timer.async_wait([&](boost::system::error_code ec) {
        this->monitor_session();
        this->schedule_monitor();
    });
}

session_manager::~session_manager() {
    stats_timer.cancel();
    session_timer.cancel();
}

void session_manager::monitor_session() {
    set<uint64_t> closedIds;
    {
        lock_guard<mutex> monitorLockGuard(monitorLock);
        lock_guard<mutex> statsLockGuard(statsLock);
        for (auto &connection : connections) {
            auto session = connection.second;
            auto sid = connection.first;
            logger::traceId = session->id;
            if (session->connected_tunnel != nullptr) {
                auto tunnelId = session->connected_tunnel->id();
                if (speeds.find(tunnelId) == speeds.end()) {
                    speeds[tunnelId] = {{0, 0}, {0, 0}};
                }
                auto readInterval = session->read_counter.inter();
                auto writeInterval = session->write_counter.inter();
                apm_logger::perf("st-proxy-stream", session->dimensions({{"direction", "down"}}), readInterval.second);
                apm_logger::perf("st-proxy-stream", session->dimensions({{"direction", "up"}}), writeInterval.second);
                if (readInterval.second > 0) {
                    speeds[tunnelId].first.first += readInterval.first;
                    speeds[tunnelId].first.second += readInterval.second;
                }
                if (writeInterval.second > 0) {
                    speeds[tunnelId].second.first += writeInterval.first;
                    speeds[tunnelId].second.second += writeInterval.second;
                }
            }
            logger::traceId = session->id;
            if (session->is_closed()) {
                closedIds.emplace(sid);
            } else if (session->is_connect_timeout()) {
                session->shutdown();
                logger::ERROR << "session manager shutdown connect timeout session" << session->idStr() << END;
            } else if (!session->is_transmitting()) {
                session->shutdown();
                logger::ERROR << "session manager shutdown noRead noWrite session" << session->idStr() << END;
            }
        }
    }
    for (unsigned long closedId : closedIds) {
        destroy(closedId);
    }
}
