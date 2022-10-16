//
// Created by codingdie on 2020/6/30.
//

#include "proxy_server.h"
#include "nat_utils.h"
#include "quality_analyzer.h"
#include "session_manager.h"
#include "st.h"
#include <boost/process.hpp>
#include <boost/thread.hpp>
using namespace std;
using namespace st::proxy;
proxy_server::proxy_server()
    : state(0), manager(nullptr), console(config::uniq().console_ip, config::uniq().console_port) {
    try {
        default_acceptor =
                new ip::tcp::acceptor(boss_ctx, tcp::endpoint(boost::asio::ip::make_address_v4(config::uniq().ip),
                                                              st::proxy::config::uniq().port));
        net_test_acceptor =
                new ip::tcp::acceptor(boss_ctx, tcp::endpoint(boost::asio::ip::make_address_v4(config::uniq().ip),
                                                              st::proxy::config::uniq().port + 1));
    } catch (const boost::system::system_error &e) {
        logger::ERROR << "bind address error" << st::proxy::config::uniq().ip << st::proxy::config::uniq().port
                      << e.what() << END;
        exit(1);
    }
    config_console();
}
void proxy_server::config_console() {
    console.desc.add_options()("ip", boost::program_options::value<string>()->default_value(""),
                               "ip")("domain", boost::program_options::value<string>()->default_value(""),
                                     "domain")("help", "produce help message");
    console.impl = [](const vector<string> &commands, const boost::program_options::variables_map &options) {
        auto command = utils::strutils::join(commands, " ");
        std::pair<bool, std::string> result = make_pair(false, "not invalid command");
        string domain;
        string ip;
        if (options.count("domain")) {
            domain = options["domain"].as<string>();
        }
        if (options.count("ip")) {
            ip = options["ip"].as<string>();
        }
        if (command == "proxy analyse") {
            if (!domain.empty()) {
                return make_pair(true, quality_analyzer::uniq().analyse_domain(domain));
            }
            if (!ip.empty()) {
                return make_pair(true, quality_analyzer::uniq().analyse_ip(utils::ipv4::str_to_ip(ip)));
            }
        } else if (command == "proxy blacklist") {
            string str;
            vector<std::string> ips = st::proxy::shm::uniq().forbid_ip_list();
            for (const auto &ip : ips) {
                auto domains = st::dns::shm::share().reverse_resolve_all(ipv4::str_to_ip(ip));
                str.append(ip).append("\t").append(join(domains, ",")).append("\n");
            }
            strutils::trim(str);
            return make_pair(true, str);
        }
        return result;
    };
    console.start();
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
    for (auto ip : st::proxy::config::uniq().whitelistIPs) {
        if (!nat_utils::INSTANCE.addToWhitelist(ip)) {
            return false;
        }
        logger::INFO << "add nat whitelist" << ipv4::ip_to_str(ip) << END;
    }
    return true;
}


bool proxy_server::intercept_nat_traffic(bool intercept) {
    string command = "sh " + st::proxy::config::uniq().baseConfDir + "/nat/init.sh " + (intercept ? "" : "clean");
    string result;
    string error;
    if (shell::exec(command, result, error)) {
        return true;
    } else {
        logger::ERROR << "intercept nat traffic error!" << error << END;
        return false;
    }
}


void proxy_server::start() {
    if (!init()) {
        return;
    }
    vector<thread> threads;
    auto worker_num = std::max(1U, std::thread::hardware_concurrency() * 2) + 1;
    for (auto i = 0; i < worker_num; i++) {
        auto ic = new boost::asio::io_context();
        auto iw = new boost::asio::io_context::work(*ic);
        worker_ctxs.emplace_back(ic);
        workers.emplace_back(iw);
    }
    for (auto i = 0; i < worker_num - 1; i++) {
        threads.emplace_back([=]() {
            auto ic = worker_ctxs.at(i);
            this->accept(ic, default_acceptor, "default");
            this->accept(ic, net_test_acceptor, "net_test");
            ic->run();
        });
    }
    io_context *schedule_ic = worker_ctxs.at(worker_num - 1);
    threads.emplace_back([=]() { schedule_ic->run(); });
    manager = new session_manager(schedule_ic);
    quality_analyzer::uniq().set_io_context(schedule_ic);
    logger::INFO << "st-proxy start with" << worker_num << "worker, listen at"
                 << st::proxy::config::uniq().ip + ":" + to_string(st::proxy::config::uniq().port) << END;
    this->state = 1;
    boss_ctx.run();
    for (auto &th : threads) {
        th.join();
    }
    delete manager;
    quality_analyzer::uniq().set_io_context(nullptr);
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
void proxy_server::accept(io_context *context, tcp::acceptor *acceptor, const string &tag) {
    auto *session = new proxy_session(*context, tag);
    acceptor->async_accept(session->client_sock, [=](const boost::system::error_code &error) {
        if (!acceptor->is_open() || state == 2) {
            return;
        }
        if (!error) {
            manager->add(session);
        }
        this->accept(context, default_acceptor, "default");
    });
}
