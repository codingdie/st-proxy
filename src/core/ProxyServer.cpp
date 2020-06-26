//
// Created by codingdie on 2020/6/30.
//

#include "ProxyServer.h"
#include "NATUtils.h"
#include "TCPSessionManager.h"
#include "utils/STUtils.h"
#include <boost/process.hpp>

using namespace std;

ProxyServer::ProxyServer(Config &config) : config(config) {
    try {
        serverAcceptor = new ip::tcp::acceptor(
                ioContext, tcp::endpoint(boost::asio::ip::make_address_v4(config.ip), config.port));
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
        if (addStreamTunnelToWhitelist()) {
            if (interceptNatTraffic(true)) {
                if (resolveWhitelistDomain()) {
                    return true;
                }
            }
        }
    };
    return false;
}

bool ProxyServer::addStreamTunnelToWhitelist() const {
    for (auto it = config.tunnels.begin(); it != config.tunnels.end(); it++) {
        auto streamTunnel = *it.base();
        auto realServerHostsStr = streamTunnel->realServerHost;
        auto realServerHosts = st::utils::strutils::split(realServerHostsStr, ",");
        for (auto realServerHost : realServerHosts) {
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
                        Logger::INFO << "addStreamTunnelToWhitelist resolve" << realServerHost
                                     << "failed! tryTime:" << tryTime << END;
                        this_thread::sleep_for(std::chrono::seconds(10));
                    }
                }
                if (ips.empty()) {
                    Logger::ERROR
                            << "addStreamTunnelToWhitelist final error! resolve domain failed!"
                            << realServerHost << END;
                    return false;
                }

                for (auto it = ips.begin(); it != ips.end(); it++) {
                    auto ip = *it;
                    streamTunnel->realServerIPs.emplace(ip);
                    if (!NATUtils::INSTANCE.addToNatWhitelist(ip)) {
                        return false;
                    }
                }
                Logger::INFO << "addToNatWhitelist" << realServerHost << ipv4::ipsToStr(ips) << END;
            }
        }
    }
    return true;
}


bool ProxyServer::resolveWhitelistDomain() {
    io_context ioContext;
    tcp::resolver slv(ioContext);
    for (auto it = config.tunnels.begin(); it != config.tunnels.end(); it++) {
        auto streamTunnel = *it.base();
        auto whitelistHosts = streamTunnel->whitelistHosts;
        for (auto host : whitelistHosts) {
            if (!host.empty()) {
                vector<uint32_t> ips;
                if (config.dns.empty()) {
                    ips = dns::query(host);
                } else {
                    ips = dns::query(config.dns, host);
                }
                Logger::INFO << "resolveWhitelistDomain" << host << ipv4::ipsToStr(ips) << END;
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
        // Logger::INFO << result << END;
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
    boost::asio::io_context::work ioContextWork(ioContext);
    vector<thread> threads;
    for (int i = 0; i < config.parallel; i++) {
        threads.emplace_back([&]() {
            accept();
            ioContext.run();
        });
    }
    Logger::INFO << "st-proxy server started, listen at" << config.ip + ":" + to_string(config.port)
                 << END;
    for (auto &th : threads) {
        th.join();
    }
    Logger::INFO << "st-proxy end" << END;
}

void ProxyServer::accept() {
    tcp::socket rSocket(ioContext);
    serverAcceptor->async_accept(
            [this](boost::system::error_code error, boost::asio::ip::tcp::socket socket) {
                // Check whether the server was stopped by a signal before this
                // completion handler had a chance to run.
                if (!serverAcceptor->is_open()) {
                    return;
                }
                if (!error) {
                    TCPSessionManager::INSTANCE->addNewSession(socket, config);
                }
                accept();
            });
}
