//
// Created by codingdie on 2020/6/30.
//

#include "proxy_server.h"
#include "nat_utils.h"
#include "session_manager.h"
#include "utils/utils.h"
#include <boost/process.hpp>
#include <boost/thread.hpp>
using namespace std;

proxy_server::proxy_server() : state(0), manager(nullptr) {
    try {
        connection_acceptor = new ip::tcp::acceptor(
                boss_ctx, tcp::endpoint(boost::asio::ip::make_address_v4(st::proxy::config::INSTANCE.ip),
                                        st::proxy::config::INSTANCE.port));
        boost::asio::ip::tcp::acceptor::keep_alive option(true);
        connection_acceptor->set_option(option);
    } catch (const boost::system::system_error &e) {
        logger::ERROR << "bind address error" << st::proxy::config::INSTANCE.ip << st::proxy::config::INSTANCE.port
                      << e.what() << END;
        exit(1);
    }
}

bool proxy_server::init() {
    srand(time::now());
    if (intercept_nat_traffic(false)) {
        if (add_nat_whitelist()) {
            if (intercept_nat_traffic(true)) {
                return true;
            }
        }
    }
    return false;
}

bool proxy_server::add_nat_whitelist() {
    for (auto ip : st::proxy::config::INSTANCE.whitelistIPs) {
        if (!nat_utils::INSTANCE.addToWhitelist(ip)) {
            return false;
        }
        logger::INFO << "add_nat_whitelist" << ipv4::ip_to_str(ip) << END;
    }
    return true;
}


bool proxy_server::intercept_nat_traffic(bool intercept) {
    string command = "sh " + st::proxy::config::INSTANCE.baseConfDir + "/nat/init.sh " + (intercept ? "" : "clean");
    string result;
    string error;
    if (shell::exec(command, result, error)) {
        return true;
    } else {
        logger::ERROR << "intercept_nat_traffic error!" << error << END;
        return false;
    }
}


void proxy_server::start() {
    if (!init()) {
        return;
    }
    vector<thread> threads;
    auto worker_num = std::max(1U, std::thread::hardware_concurrency()) + 1;
    for (auto i = 0; i < worker_num; i++) {
        auto ic = new boost::asio::io_context();
        auto iw = new boost::asio::io_context::work(*ic);
        worker_ctxs.emplace_back(ic);
        workers.emplace_back(iw);
    }
    for (auto i = 0; i < worker_num - 1; i++) {
        threads.emplace_back([=]() {
            auto ic = worker_ctxs.at(i);
            this->accept(ic);
            ic->run();
        });
    }
    io_context *schedule_ic = worker_ctxs.at(worker_num - 1);
    manager = new session_manager(schedule_ic);
    threads.emplace_back([=]() { schedule_ic->run(); });

    logger::INFO << "st-proxy server started, listen at"
                 << st::proxy::config::INSTANCE.ip + ":" + to_string(st::proxy::config::INSTANCE.port) << END;
    this->state = 1;
    boss_ctx.run();
    for (auto &th : threads) {
        th.join();
    }
    delete manager;
    logger::INFO << "st-proxy server stopped" << END;
}
void proxy_server::shutdown() {
    intercept_nat_traffic(false);
    this->state = 2;
    boss_ctx.stop();
    for (boost::asio::io_context *ioContext : worker_ctxs) {
        ioContext->stop();
    }
    for (boost::asio::io_context::work *iw : workers) {
        delete iw;
    }
}

void proxy_server::wait_start() {
    cout << state << endl;
    while (state.load() != 1) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    cout << state << endl;
}
void proxy_server::accept(io_context *context) {
    auto *session = new proxy_session(*context);
    connection_acceptor->async_accept(session->client_sock, [=](const boost::system::error_code &error) {
        if (!connection_acceptor->is_open() || state == 2) {
            return;
        }
        if (!error) {
            manager->add(session);
        }
        this->accept(context);
    });
}
