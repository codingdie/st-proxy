//
// Created by codingdie on 2020/10/5.
//

#include "session_manager.h"
#include <mutex>

void session_manager::add(proxy_session *session) {
    session->start();
    ic->post([=]() { connections.emplace(make_pair(session->id, session)); });
}

session_manager::session_manager(io_context *ic)
    : random_engine(time::now()), random_range(1024, 12000), session_timer(*ic), ic(ic) {
    schedule_monitor();
}


bool session_manager::destroy(uint64_t sid) {
    auto iterator = connections.find(sid);
    if (iterator != connections.end()) {
        proxy_session *session = iterator->second;
        connections.erase(iterator);
        delete session;
        return true;
    }
    return false;
}

uint16_t session_manager::guess_unused_port() { return random_range(random_engine); }

void session_manager::schedule_monitor() {
    session_timer.expires_from_now(boost::posix_time::seconds(10));
    session_timer.async_wait([&](boost::system::error_code ec) {
        this->monitor_session();
        this->schedule_monitor();
    });
}

session_manager::~session_manager() { session_timer.cancel(); }

void session_manager::monitor_session() {
    set<uint64_t> closed_session_ids;
    unsigned long session_size = connections.size();
    for (auto &connection : connections) {
        auto session = connection.second;
        auto sid = connection.first;
        logger::traceId = session->id;
        if (session->connected_tunnel != nullptr) {
            auto tunnelId = session->connected_tunnel->id();
            auto readInterval = session->read_counter.inter();
            auto writeInterval = session->write_counter.inter();
            apm_logger::perf("st-proxy-stream", session->dimensions({{}}),
                             {{"down", readInterval.second}, {"up", writeInterval.second}});
        }
        logger::traceId = session->id;
        if (session->is_closed()) {
            closed_session_ids.emplace(sid);
        } else if (session->is_connect_timeout()) {
            session->shutdown();
            logger::WARN << "session manager shutdown connect timeout session" << session->idStr() << END;
        } else if (!session->is_transmitting()) {
            session->shutdown();
            logger::WARN << "session manager shutdown noRead noWrite session" << session->idStr() << END;
        }
    }
    for (uint64_t session_id : closed_session_ids) {
        if (!destroy(session_id)) {
            logger::ERROR << "session manager destroy session failed!" << session_id << END;
        }
    }
    logger::INFO << "session manager destroy" << closed_session_ids.size()
                 << "session, origin session size:" << session_size << "final session size:" << connections.size()
                 << END;

    apm_logger::perf("st-proxy-session", {{}}, {{"total", connections.size()}, {"destroy", closed_session_ids.size()}});
}
