//
// Created by codingdie on 2020/6/30.
//

#include "ProxyServer.h"
#include "NATUtils.h"
#include "SessionManager.h"
#include "utils/STUtils.h"
#include <boost/process.hpp>

using namespace std;

ProxyServer::ProxyServer(Config &config) : config(config), state(0) {
    try {
        serverAcceptor = new ip::tcp::acceptor(ioContext, tcp::endpoint(boost::asio::ip::make_address_v4(config.ip), config.port));
        boost::asio::ip::tcp::acceptor::keep_alive option(true);
        serverAcceptor->set_option(option);
    } catch (const boost::system::system_error &e) {
        Logger::ERROR << "bind address error" << config.ip << config.port << e.what() << END;
        exit(1);
    }
}

bool ProxyServer::init() {
    srand(time::now());
    if (interceptNatTraffic(false)) {
        if (addNatWhitelist()) {
            if (interceptNatTraffic(true)) {
                if (addTunnelWhitelist()) {
                    return true;
                }
            }
        }
    };
    return false;
}

bool ProxyServer::addNatWhitelist() const {
    for (auto realServerHost : this->config.whitelist) {
        if (!realServerHost.empty()) {
            vector<uint32_t> ips;
            int tryTime = 0;
            while (tryTime++ < 3) {
                if (config.dns.empty()) {
                    ips = dns::query(realServerHost);
                } else {
                    ips = dns::query(config.dns, realServerHost);
                }
                if (ips.empty()) {
                    Logger::INFO << "addNatWhitelist resolve" << realServerHost << "failed! tryTime:" << tryTime << END;
                    this_thread::sleep_for(std::chrono::seconds(10));
                }
            }
            if (ips.empty()) {
                Logger::ERROR << "addNatWhitelist final error! resolve domain failed!" << realServerHost << END;
                return false;
            }

            for (auto it = ips.begin(); it != ips.end(); it++) {
                auto ip = *it;
                if (!NATUtils::INSTANCE.addToWhitelist(ip)) {
                    return false;
                }
            }
            Logger::INFO << "addToWhitelist" << realServerHost << ipv4::ipsToStr(ips) << END;
        }
    }
    return true;
}


bool ProxyServer::addTunnelWhitelist() {
    io_context ioContext;
    tcp::resolver slv(ioContext);
    for (auto it = config.tunnels.begin(); it != config.tunnels.end(); it++) {
        auto streamTunnel = *it.base();
        for (auto host : streamTunnel->whitelist) {
            if (!host.empty()) {
                vector<uint32_t> ips;
                if (config.dns.empty()) {
                    ips = dns::query(host);
                } else {
                    ips = dns::query(config.dns, host);
                }
                Logger::INFO << "addTunnelWhitelist" << host << ipv4::ipsToStr(ips) << END;
                for (auto it = ips.begin(); it != ips.end(); it++) {
                    streamTunnel->whitelistIPs.emplace(*it);
                }
            }
        }
    }
    return true;
}

bool ProxyServer::interceptNatTraffic(bool intercept) const {
    string command = "sh " + config.baseConfDir + "/nat/init.sh " + (intercept ? "" : "clean");
    Logger::INFO << command << END;
    string result;
    string error;
    if (shell::exec(command, result, error)) {
        Logger::DEBUG << result << END;
        return true;
    } else {
        Logger::ERROR << error << END;
        return false;
    }
}


void ProxyServer::start() {
    if (!init()) {
        return;
    }
    ioWoker = new boost::asio::io_context::work(ioContext);
    vector<thread> threads;
    for (int i = 0; i < config.parallel; i++) {
        threads.emplace_back([&]() {
            accept();
            ioContext.run();
        });
    }
    Logger::INFO << "st-proxy server started, listen at" << config.ip + ":" + to_string(config.port) << END;
    this->state = 1;
    for (auto &th : threads) {
        th.join();
    }
    Logger::INFO << "st-proxy end" << END;
}
void ProxyServer::shutdown() {
    interceptNatTraffic(false);
    this->state = 2;
    delete ioWoker;
    ioContext.stop();
    Logger::INFO << "st-proxy server stoped, listen at" << config.ip + ":" + to_string(config.port) << END;
}

void ProxyServer::waitStart() {
    cout << state << endl;
    while (state == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    cout << state << endl;
}
void ProxyServer::accept() {
    tcp::socket rSocket(ioContext);
    serverAcceptor->async_accept([this](boost::system::error_code error, boost::asio::ip::tcp::socket socket) {
        // Check whether the server was stopped by a signal before this
        // completion handler had a chance to run.
        if (!serverAcceptor->is_open() || state == 2) {
            return;
        }
        if (!error) {
            SessionManager::INSTANCE->addNewSession(socket, config);
        }
        accept();
    });
}
