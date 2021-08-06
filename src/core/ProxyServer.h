//
// Created by codingdie on 2020/6/30.
//

#ifndef ST_PROXY_PROXYSERVER_H
#define ST_PROXY_PROXYSERVER_H

#include "Config.h"
#include "utils/STUtils.h"
#include <boost/asio.hpp>
#include <boost/thread.hpp>

using namespace boost::asio;
using namespace boost::asio::ip;
using namespace st::proxy;

class ProxyServer {
public:
    ProxyServer();

    void start();

    void waitStart();

    void shutdown();

    static ProxyServer INSTANCE;

private:
    std::atomic<uint8_t> state;
    io_context bossCtx;
    vector<io_context *> workCtxs;
    thread_pool pool;
    ip::tcp::acceptor *serverAcceptor;
    vector<io_context::work *> wokers;
    void accept(io_context *context);

    bool init();

    bool interceptNatTraffic(bool Intercept) const;

    bool addNatWhitelist() const;
    bool addTunnelWhitelist();
};


#endif//ST_PROXY_PROXYSERVER_H
