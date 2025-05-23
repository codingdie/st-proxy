//
// Created by codingdie on 2020/10/5.
//

#include "session_manager.h"
#include <mutex>

session_manager::session_manager() : ctx(), random_engine(time::now()), random_range(1024, 12000), session_timer(ctx) {
    worker = new boost::asio::io_context::work(ctx);
    th = new thread([this]() { this->ctx.run(); });
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


session_manager &session_manager::uniq() {
    static session_manager instance;
    return instance;
}

void session_manager::add(proxy_session *session) {
    session->start();
    ctx.post([=]() { connections.emplace(session->id, session); });
}

uint16_t session_manager::guess_unused_port() { return random_range(random_engine); }

void session_manager::schedule_monitor() {
    session_timer.expires_from_now(boost::posix_time::seconds(10));
    session_timer.async_wait([&](boost::system::error_code ec) {
        this->monitor_session();
        this->schedule_monitor();
    });
}

session_manager::~session_manager() {
    session_timer.cancel();
    ctx.stop();
    delete worker;
    th->join();
    delete th;
}

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
            logger::WARN << "session manager shutdown connect timeout session" << session->id_str() << END;
        } else if (!session->is_transmitting()) {
            session->shutdown();
            logger::WARN << "session manager shutdown noRead noWrite session" << session->id_str() << END;
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
vector<string> session_manager::status() {
    vector<string> results;
    bool success = false;
    ctx.post([&results, &success, this]() {
        for (const auto &item : connections) {
            proxy_session *session = item.second;
            results.emplace_back(session->status());
        }
        success = true;
    });
    int i = 0;
    while (i++ < 10) {
        if (success) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    return results;
}
