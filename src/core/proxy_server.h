//
// Created by codingdie on 2020/6/30.
//

#ifndef ST_PROXY_PROXY_SERVER_H
#define ST_PROXY_PROXY_SERVER_H

#include "config.h"
#include "session_manager.h"
#include "st.h"
#include <boost/asio.hpp>
#include <boost/thread.hpp>
using namespace boost::asio;
using namespace boost::asio::ip;
using namespace st::proxy;

class proxy_server {
public:
    proxy_server();

    void start();

    void wait_start();

    void shutdown();


private:
    std::atomic<uint8_t> state;
    io_context boss_ctx;
    vector<io_context *> worker_ctxs;
    thread_pool pool;
    ip::tcp::acceptor *connection_acceptor;
    vector<io_context::work *> workers;
    session_manager *manager;
    st::console::udp_console console;
    void accept(io_context *context);

    bool init();

    static bool intercept_nat_traffic(bool intercept);

    static bool add_nat_whitelist();

    void config_console();
};


#endif//ST_PROXY_PROXY_SERVER_H
