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
    ProxyServer(Config &config);

    void start();

    static ProxyServer INSTANCE;

private:
    io_context ioContext;
    thread_pool pool;
    Config &config;
    ip::tcp::acceptor *serverAcceptor;
    void accept();

    bool init();

    bool interceptNatTraffic(bool Intercept) const;

    bool addStreamTunnelToWhitelist() const;
    bool resolveWhitelistDomain();
};


#endif//ST_PROXY_PROXYSERVER_H
