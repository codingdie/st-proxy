//
// Created by codingdie on 2020/6/30.
//

#include "proxy_server.h"
#include "nat_utils.h"
#include "net_test_manager.h"
#include "quality_analyzer.h"
#include "session_manager.h"
#include "virtual_port_manager.h"
#include <boost/process.hpp>
#include <boost/thread.hpp>
using namespace std;
using namespace st::proxy;
proxy_server::proxy_server()
    : state(0), manager(nullptr), console(config::uniq().console_ip, config::uniq().console_port) {
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
                *worker_ctxs[0],
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
    config_console();
}
void proxy_server::config_console() {
    console.desc.add_options()("ip", boost::program_options::value<string>()->default_value(""), "ip");
    console.desc.add_options()("port", boost::program_options::value<uint16_t>()->default_value(443), "port");
    console.desc.add_options()("domain", boost::program_options::value<string>()->default_value(""), "domain");
    console.desc.add_options()("area", boost::program_options::value<string>()->default_value(""), "area");
    console.impl = [](const vector<string> &commands, const boost::program_options::variables_map &options) {
        auto command = utils::strutils::join(commands, " ");
        std::pair<bool, std::string> result = make_pair(false, "not invalid command");
        string domain = options["domain"].as<string>();
        string area = options["area"].as<string>();
        string ipStr = options["ip"].as<string>();
        uint32_t ip = 0;
        uint16_t port = options["port"].as<uint16_t>();
        if (!ipStr.empty()) {
            ip = ipv4::str_to_ip(ipStr);
        }
        if (command == "proxy analyse ip tunnels" && ip > 0) {
            return make_pair(true, quality_analyzer::uniq().analyse_ip_tunnels(ip));
        } else if (command == "proxy analyse ip" && ip > 0) {
            return make_pair(true, quality_analyzer::uniq().analyse_ip(ip));
        } else if (command == "proxy analyse tunnel") {
            return make_pair(true, quality_analyzer::uniq().analyse_tunnel());
        } else if (command == "proxy analyse delete") {
            if (!domain.empty()) {
                quality_analyzer::uniq().delete_record(domain);
                return make_pair(false, string(domain));
            }
            if (ip > 0) {
                quality_analyzer::uniq().delete_record(ip);
                return make_pair(false, ipStr);
            }
        } else if (command == "proxy analyse delete all") {
            quality_analyzer::uniq().delete_all_record();
            return make_pair(true, string("delete all!"));

        } else if (command == "proxy blacklist") {
            string str;
            //            vector<std::string> ips = st::proxy::shm::uniq().forbid_ip_list();
            //            for (const auto &blackIp : ips) {
            //                auto domains = st::dns::shm::share().reverse_resolve_all(ipv4::str_to_ip(blackIp));
            //                str.append(blackIp).append("\t").append(join(domains, ",")).append("\n");
            //            }
            strutils::trim(str);
            return make_pair(true, str);
        } else if (command == "proxy net test") {
            if (ip > 0) {
                net_test_manager::uniq().test(ip, port, 100);
                return make_pair(true, "add net test " + ipStr);
            }
        } else if (command == "proxy register area virtual port") {
            if (ip > 0 && port > 0 && !area.empty()) {
                uint16_t virtual_port = virtual_port_manager::uniq().register_area_virtual_port(ip, port, area);
                return make_pair(true, to_string(virtual_port));
            }
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
    for (auto ip : st::proxy::config::uniq().ip_whitelist) {
        if (!nat_utils::INSTANCE.addToWhitelist(ip)) {
            return false;
        }
        logger::INFO << "add nat whitelist" << ipv4::ip_to_str(ip) << END;
    }
    return true;
}


bool proxy_server::intercept_nat_traffic(bool intercept) {
    auto &targets = config::uniq().proxy_target;
    string proxy_dist_port = "";
    if (targets.find("all") == targets.end()) {
        if (targets.find("dns") != targets.end()) {
            proxy_dist_port += "53,853,";
        }
        if (targets.find("http") != targets.end()) {
            proxy_dist_port += "80,443,";
        }
    }
    if (!proxy_dist_port.empty()) {
        proxy_dist_port = proxy_dist_port.substr(0, proxy_dist_port.size() - 1);
    }
    string command = "sh " + st::proxy::config::uniq().base_conf_dir + "/nat/rule.sh " +
                     (intercept ? "intercept" : "clean") + " " + proxy_dist_port;
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
    io_context *schedule_ic = worker_ctxs.at(worker_ctxs.size() - 1);
    threads.emplace_back([=]() { schedule_ic->run(); });
    quality_analyzer::uniq().start(schedule_ic);
    manager = new session_manager(schedule_ic);
    schedule_timer = new deadline_timer(*schedule_ic);
    schedule();
    unsigned int cpu_count = std::thread::hardware_concurrency();
    for (auto i = 0; i < 2; i++) {
        threads.emplace_back([=]() {
            auto ic = worker_ctxs.at(i);
            ic->run();
        });
    }
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
    for (auto &th : threads) {
        th.join();
    }
    delete manager;
    quality_analyzer::uniq().stop();
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
    intercept_nat_traffic(false);
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
        add_nat_whitelist();
        this->schedule();
    });
}
