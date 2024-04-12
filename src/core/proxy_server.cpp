//
// Created by codingdie on 2020/6/30.
//

#include "proxy_server.h"
#include "nat_utils.h"
#include "session_manager.h"
#include "virtual_port_manager.h"
#include <boost/process.hpp>
#include <boost/thread.hpp>
#include "console/proxy_console.h"
using namespace std;
using namespace st::proxy;
proxy_server::proxy_server() : state(0), manager(nullptr) {
    unsigned int cpu_count = std::thread::hardware_concurrency();
    auto worker_num = 2 + std::max(1U, cpu_count * 2);
    for (auto i = 0; i < worker_num; i++) {
        auto ic = new boost::asio::io_context();
        auto iw = new boost::asio::io_context::work(*ic);
        worker_ctxs.emplace_back(ic);
        workers.emplace_back(iw);
    }
    try {
        default_acceptor = new ip::tcp::acceptor(
                *worker_ctxs[1],
                tcp::endpoint(boost::asio::ip::make_address_v4(config::uniq().ip), st::proxy::config::uniq().port));

        boost::asio::ip::tcp::acceptor::keep_alive option(true);
        default_acceptor->set_option(option);

        using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
        boost::system::error_code ec;
#ifdef TCP_FASTOPEN
        default_acceptor->set_option(fastopen(20), ec);
#endif
        default_acceptor->set_option(tcp::no_delay(true));
    } catch (const boost::system::system_error &e) {
        logger::ERROR << "bind address error" << st::proxy::config::uniq().ip << st::proxy::config::uniq().port
                      << e.what() << END;
        exit(1);
    }
}


bool proxy_server::init() {
    srand(time::now());
    if (nat_utils::uniq().intercept_nat_traffic(false)) {
        if (nat_utils::uniq().add_nat_whitelist()) {
            if (nat_utils::uniq().intercept_nat_traffic(true)) {
                return true;
            }
        }
    }
    return false;
}


void proxy_server::start() {
    if (!init()) {
        return;
    }
    vector<thread> threads;
    unsigned int cpu_count = std::thread::hardware_concurrency();
    threads.reserve(2 + 2 * cpu_count);
    for (auto i = 0; i < 2; i++) {
        threads.emplace_back([=]() {
            auto ic = worker_ctxs.at(i);
            ic->run();
        });
    }
    io_context *schedule_ic = worker_ctxs.at(0);
    schedule_timer = new deadline_timer(*schedule_ic);
    manager = new session_manager(schedule_ic);
    schedule();

    for (auto i = 2; i < 2 + 2 * cpu_count; i++) {
        threads.emplace_back([=]() {
            auto ic = worker_ctxs.at(i);
            this->accept(ic, default_acceptor);
            ic->run();
        });
    }

    logger::INFO << "st-proxy start with" << worker_ctxs.size() - 2 << "worker, listen at"
                 << st::proxy::config::uniq().ip + ":" + to_string(st::proxy::config::uniq().port) << END;
    this->state = 1;
    proxy_console console;
    console.start();
    for (auto &th : threads) {
        th.join();
    }
    delete manager;
    logger::INFO << "st-proxy server stopped" << END;
}
void proxy_server::shutdown() {
    this->state = 2;
    for (boost::asio::io_context *ioContext : worker_ctxs) {
        ioContext->stop();
    }
    for (boost::asio::io_context::work *iw : workers) {
        delete iw;
    }
    delete schedule_timer;
    this->schedule_timer = nullptr;
    nat_utils::uniq().intercept_nat_traffic(false);
}

void proxy_server::wait_start() {
    cout << state << endl;
    while (state.load() != 1) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    cout << state << endl;
}
void proxy_server::accept(io_context *context, tcp::acceptor *acceptor) {
    auto *session = new proxy_session(*context);
    acceptor->async_accept(session->client_sock, [=](const boost::system::error_code &error) {
        if (!acceptor->is_open() || state == 2) {
            delete session;
            return;
        }
        if (!error) {
            manager->add(session);
        } else {
            delete session;
        }
        this->accept(context, acceptor);
    });
}

void proxy_server::schedule() {
    schedule_timer->expires_from_now(boost::posix_time::seconds(60));
    schedule_timer->async_wait([&](boost::system::error_code ec) {
        config::uniq().parse_whitelist_to_ips();
        nat_utils::uniq().add_nat_whitelist();
        this->schedule();
    });
}
