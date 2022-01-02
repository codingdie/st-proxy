//
// Created by codingdie on 2020/6/30.
//

#include "ProxyServer.h"
#include "NATUtils.h"
#include "SessionManager.h"
#include "utils/STUtils.h"
#include <boost/process.hpp>

using namespace std;

ProxyServer::ProxyServer() : state(0) {
    try {
        serverAcceptor = new ip::tcp::acceptor(
                bossCtx, tcp::endpoint(boost::asio::ip::make_address_v4(st::proxy::Config::INSTANCE.ip),
                                       st::proxy::Config::INSTANCE.port));
        boost::asio::ip::tcp::acceptor::keep_alive option(true);
        serverAcceptor->set_option(option);
    } catch (const boost::system::system_error &e) {
        Logger::ERROR << "bind address error" << st::proxy::Config::INSTANCE.ip << st::proxy::Config::INSTANCE.port
                      << e.what() << END;
        exit(1);
    }
}

bool ProxyServer::init() {
    srand(time::now());
    if (interceptNatTraffic(false)) {
        if (addNatWhitelist()) {
            if (interceptNatTraffic(true)) {
                return true;
            }
        }
    };
    return false;
}

bool ProxyServer::addNatWhitelist() const {
    for (auto realServerHost : st::proxy::Config::INSTANCE.whitelist) {
        if (!realServerHost.empty()) {
            vector<uint32_t> ips;
            int tryTime = 0;
            while (tryTime++ < 3) {
                ips = st::proxy::Config::INSTANCE.resovleHost(realServerHost);
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
            Logger::INFO << "addNatWhitelist" << realServerHost << ipv4::ipsToStr(ips) << END;
        }
    }
    return true;
}


bool ProxyServer::interceptNatTraffic(bool intercept) const {
    string command = "sh " + st::proxy::Config::INSTANCE.baseConfDir + "/nat/init.sh " + (intercept ? "" : "clean");
    string result;
    string error;
    if (shell::exec(command, result, error)) {
        return true;
    } else {
        Logger::ERROR << "interceptNatTraffic eror!" << error << END;
        return false;
    }
}


void ProxyServer::start() {
    if (!init()) {
        return;
    }
    vector<thread> threads;
    for (int i = 0; i < st::proxy::Config::INSTANCE.parallel; i++) {
        boost::asio::io_context *ioContext = new boost::asio::io_context();
        boost::asio::io_context::work *ioWoker = new boost::asio::io_context::work(*ioContext);
        workCtxs.push_back(ioContext);
        wokers.push_back(ioWoker);
        threads.emplace_back([=]() {
            this->accept(ioContext);
            ioContext->run();
        });
    }
    Logger::INFO << "st-proxy server started, listen at"
                 << st::proxy::Config::INSTANCE.ip + ":" + to_string(st::proxy::Config::INSTANCE.port) << END;
    this->state = 1;
    bossCtx.run();
    for (auto &th : threads) {
        th.join();
    }
    Logger::INFO << "st-proxy server stopped" << END;
}
void ProxyServer::shutdown() {
    interceptNatTraffic(false);
    this->state = 2;
    bossCtx.stop();
    for (boost::asio::io_context::work *ioWoker : wokers) {
        delete ioWoker;
    }
    for (boost::asio::io_context *ioContext : workCtxs) {
        ioContext->stop();
    }
}

void ProxyServer::waitStart() {
    cout << state << endl;
    while (state == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    cout << state << endl;
}
void ProxyServer::accept(io_context *context) {
    Session *session = new Session(*context);
    serverAcceptor->async_accept(session->clientSock, [=](const boost::system::error_code &error) {
        if (!serverAcceptor->is_open() || state == 2) {
            return;
        }
        if (!error) {
            SessionManager::INSTANCE->addNewSession(session);
        }
        this->accept(context);
    });
}
