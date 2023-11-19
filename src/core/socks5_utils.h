//
// Created by codingdie on 6/26/23.
//

#ifndef ST_PROXY_SOCKS5_UTILS_H
#define ST_PROXY_SOCKS5_UTILS_H

#include "common.h"
#include "nat_utils.h"
#include "stream_tunnel.h"

static void bind_local_port(tcp::socket *proxy_sock, boost::system::error_code &error) {
    boost::system::error_code se;
    if (proxy_sock->is_open()) {
        proxy_sock->shutdown(boost::asio::socket_base::shutdown_both, se);
        proxy_sock->cancel(se);
        proxy_sock->close(se);
    }
    proxy_sock->open(tcp::v4(), error);
#ifdef __APPLE__
    proxy_sock.bind(tcp::endpoint("127.0.0.1", session_manager::share().guess_unused_port()), error);
    int i = 1;
    while (error && i <= 1000) {
        proxy_sock.bind(tcp::endpoint("127.0.0.1", session_manager::share().guess_unused_port()), error);
        i++;
    }
#endif
}

static bool init_proxy_socks(tcp::socket *proxy_sock) {
    boost::system::error_code error;
    bind_local_port(proxy_sock, error);
    if (error) {
        logger::ERROR << "init proxy socks bind local port error!" << error.message() << END;
        return false;
    }
    boost::system::error_code se;
    proxy_sock->set_option(tcp::no_delay(true));
#ifdef TCP_FASTOPEN
    using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
    boost::system::error_code ec;
    proxy_sock->set_option(fastopen(20), ec);
#endif
#ifdef linux
    nat_utils::set_mark(1024, *proxy_sock);
#endif
    return true;
}
static void connect_socks(tcp::socket *proxy_sock, const std::string &socks_ip, std::uint32_t socks_port,
                          const tcp::endpoint &dist_end, int timeout,
                          const std::function<void(bool)> &complete_handler) {
    if (!init_proxy_socks(proxy_sock)) {
        delete proxy_sock;
        complete_handler(false);
        return;
    }

    auto out_buffer_p = st::mem::pmalloc(1024);
    auto in_buffer_p = st::mem::pmalloc(1024);
    auto out_buffer = out_buffer_p.first;
    auto in_buffer = out_buffer_p.first;
    auto proxyEnd = tcp::endpoint(make_address(socks_ip), socks_port);
    const auto &executor = proxy_sock->get_executor();
    auto *timer = new deadline_timer(executor);
    auto complete = [=](bool success) {
        timer->cancel();
        delete timer;
        if (!success) {
            boost::asio::post(proxy_sock->get_executor(), [=]() { delete proxy_sock; });
        }
        st::mem::pfree(out_buffer_p);
        st::mem::pfree(in_buffer_p);
        complete_handler(success);
    };
    timer->expires_from_now(boost::posix_time::milliseconds(timeout));
    timer->async_wait([=](boost::system::error_code ec) {
        if (ec != boost::asio::error::operation_aborted) {
            proxy_sock->shutdown(boost::asio::socket_base::shutdown_both, ec);
            proxy_sock->cancel(ec);
            proxy_sock->close(ec);
        }
    });

    proxy_sock->async_connect(proxyEnd, [=](boost::system::error_code error) {
        if (error) {
            complete(false);
        } else {
            out_buffer[0] = 0x05;
            out_buffer[1] = 0x01;
            out_buffer[2] = 0x00;
            boost::asio::async_write(
                    *proxy_sock, buffer(out_buffer, sizeof(uint8_t) * 3), boost::asio::transfer_at_least(3),
                    [=](boost::system::error_code error, size_t size) {
                        if (!error) {
                            proxy_sock->async_receive(
                                    buffer(in_buffer, sizeof(uint8_t) * 2),
                                    [=](boost::system::error_code error, size_t size) {
                                        if (!error && in_buffer[0] == 0x05 && in_buffer[1] == 0x00) {
                                            out_buffer[0] = 0x05;
                                            out_buffer[1] = 0x01;
                                            out_buffer[2] = 0x00;
                                            out_buffer[3] = 0x01;
                                            auto ipArray = dist_end.address().to_v4().to_bytes();
                                            out_buffer[4] = ipArray[0];
                                            out_buffer[5] = ipArray[1];
                                            out_buffer[6] = ipArray[2];
                                            out_buffer[7] = ipArray[3];
                                            uint16_t port = dist_end.port();
                                            out_buffer[8] = (port >> 8) & 0XFF;
                                            out_buffer[9] = port & 0XFF;
                                            boost::asio::async_write(
                                                    *proxy_sock, buffer(out_buffer, sizeof(uint8_t) * 10),
                                                    boost::asio::transfer_at_least(10),
                                                    [=](boost::system::error_code error, size_t size) {
                                                        if (error) {
                                                            complete(false);
                                                            return;
                                                        }
                                                        proxy_sock->async_receive(
                                                                buffer(in_buffer, sizeof(uint8_t) * 10),
                                                                [=](boost::system::error_code error, size_t size) {
                                                                    if (!error && in_buffer[0] == 0x05 &&
                                                                        in_buffer[1] == 0x00) {
                                                                        complete(true);
                                                                    } else {
                                                                        complete(false);
                                                                    }
                                                                });
                                                    });
                                        } else {
                                            complete(false);
                                        }
                                    });
                        } else {
                            complete(false);
                        }
                    });
        }
    });
}
#endif//ST_PROXY_SOCKS5_UTILS_H
