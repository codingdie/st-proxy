//
// Created by codingdie on 10/16/22.
//

#include "net_test_manager.h"
#include "nat_utils.h"
#include <boost/asio/ssl.hpp>
net_test_manager::net_test_manager() : ic(), iw(new io_context::work(ic)), th([this]() { ic.run(); }) {
    for (byte &i : test_request) {
        i = 0b00000000;
    }
}
net_test_manager::~net_test_manager() {
    ic.stop();
    delete iw;
    th.join();
}
net_test_manager &net_test_manager::uniq() {
    static net_test_manager instance;
    return instance;
}

void net_test_manager::tls_handshake(uint32_t dist_ip, const net_test_callback &callback) {
    string logTag = "net test tls handshake " + ipv4::ip_to_str(dist_ip) + ":443";

    boost::asio::ssl::context sslCtx(boost::asio::ssl::context::sslv23_client);
    tcp::endpoint server_endpoint(make_address_v4(dist_ip), 443);
    auto *socket = new boost::asio::ssl::stream<tcp::socket>(ic, sslCtx);
    socket->set_verify_mode(ssl::verify_peer);
    boost::system::error_code ec;
    uint32_t begin = time::now();
    auto *timer = new deadline_timer(ic);
    timer->expires_from_now(boost::posix_time::milliseconds(TEST_TIME_OUT));
    timer->async_wait([=](boost::system::error_code ec) {
        socket->async_shutdown([=](boost::system::error_code ec) {
            socket->lowest_layer().shutdown(boost::asio::socket_base::shutdown_both, ec);
            delete socket;
        });
    });
    auto complete = [=](bool valid, bool connected, uint32_t cost) {
        delete timer;
        callback(valid, connected, cost);
    };
    socket->next_layer().open(tcp::v4());
    nat_utils::set_mark(1025, socket->next_layer());
    socket->lowest_layer().async_connect(server_endpoint, [=](boost::system::error_code ec) {
        if (!ec) {
            socket->async_handshake(boost::asio::ssl::stream_base::client, [=](boost::system::error_code ec) {
                if (ec.category().name() == "asio.ssl") {
                    complete(true, true, time::now() - begin);
                } else {
                    logger::ERROR << "handshake error!" << ec.category().name() << ec.message() << END;
                    complete(false, true, time::now() - begin);
                }
            });

        } else {
            logger::ERROR << "connect error!" << ec.message() << END;
            complete(true, false, time::now() - begin);
        }
    });
}
void net_test_manager::test(uint32_t dist_ip, uint16_t port, const net_test_callback &callback) {
    if (port == 443) {
        tls_handshake(dist_ip, callback);
    } else if (port == 80) {
        random_package(dist_ip, port, callback);
    } else {
        random_package(dist_ip, port, [=](bool valid, bool connected, uint32_t cost) {
            if (valid) {
                callback(valid, connected, cost);
            } else {
                http_random(dist_ip, [=](bool valid, bool connected, uint32_t cost) {
                    if (valid) {
                        callback(valid, connected, cost);
                    } else {
                        random_package(dist_ip, 22, callback);
                    }
                });
            }
        });
    }
}
void net_test_manager::random_package(uint32_t dist_ip, uint16_t port, const net_test_callback &callback) {
    tcp::endpoint server_endpoint(make_address_v4(dist_ip), port);
    auto *socket = new tcp::socket(ic);
    uint32_t begin = time::now();
    auto *timer = new deadline_timer(ic);
    timer->expires_from_now(boost::posix_time::milliseconds(TEST_TIME_OUT));
    timer->async_wait([=](boost::system::error_code ec) {
        socket->shutdown(boost::asio::socket_base::shutdown_both, ec);
        delete socket;
    });
    socket->open(tcp::v4());
    nat_utils::set_mark(1025, *socket);
    auto complete = [=](bool valid, bool connected, uint32_t cost) {
        delete timer;
        callback(valid, connected, cost);
    };
    string logTag = "net test random package " + ipv4::ip_to_str(dist_ip) + ":" + to_string(port);
    socket->async_connect(server_endpoint, [=](boost::system::error_code ec) {
        if (!ec) {
            auto send_handler = [=](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    pair<uint8_t *, uint32_t> data = st::mem::pmalloc(2048);
                    auto receive_handler = [=](boost::system::error_code ec, std::size_t length) {
                        if (!ec) {
                            st::mem::pfree(data);
                            complete(true, true, time::now() - begin);
                        } else {
                            complete(false, true, time::now() - begin);
                            if (ec != boost::asio::error::operation_aborted) {
                                logger::ERROR << logTag << "receive test response error!"
                                              << string(ec.category().name()) + "/" + ec.message() << length << END;
                            }
                        }
                    };
                    socket->async_read_some(buffer(data.first, data.second), receive_handler);
                } else {
                    complete(false, true, time::now() - begin);
                    logger::ERROR << logTag << "send test request error!" << ec.category().name() << ec.message()
                                  << length << END;
                };
            };
            boost::asio::async_write(*socket, buffer(test_request, TEST_REQUEST_LEN), send_handler);
        } else {
            logger::ERROR << logTag << "connect error!" << ec.message() << END;
            complete(true, false, time::now() - begin);
        }
    });
}
void net_test_manager::http_random(uint32_t dist_ip, const function<void(bool, bool, uint32_t)> &callback) {
    random_package(dist_ip, 80, callback);
}
void net_test_manager::test(uint32_t dist_ip, uint16_t port, uint16_t count) {
    std::lock_guard<std::mutex> lg(mt);
    if (in_test_ips.size() < 5 && in_test_ips.emplace(dist_ip).second) {
        logger::INFO << "net test begin" << ipv4::ip_to_str(dist_ip) + ":" + to_string(port) << "count" << count
                     << END;
        auto traceId = logger::traceId;
        test_re(dist_ip, port, count, [=](bool valid, bool connected, uint32_t cost) {
            logger::traceId = traceId;
            std::lock_guard<std::mutex> lg(mt);
            in_test_ips.erase(dist_ip);
            logger::INFO << "net test end" << ipv4::ip_to_str(dist_ip) + ":" + to_string(port) << END;
        });
    }
}

void net_test_manager::test_re(uint32_t dist_ip, uint16_t port, uint16_t count, const net_test_callback &callback) {
    if (count <= 0) {
        callback(false, false, 0);
    } else {
        test(dist_ip, port,
             [=](bool valid, bool connected, uint32_t cost) { test_re(dist_ip, port, count - 1, callback); });
    }
}