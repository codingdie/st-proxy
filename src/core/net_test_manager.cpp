//
// Created by codingdie on 10/16/22.
//

#include "net_test_manager.h"
#include "command/dns_command.h"
#include "nat_utils.h"
#include <boost/asio/ssl.hpp>
net_test_manager::net_test_manager()
    : ic(), iw(new io_context::work(ic)), th([this]() { ic.run(); }),
      t_queue("st-proxy-net-test", 10, 30, [this](const st::task::priority_task<test_case> &task) {
          const test_case &tc = task.get_input();
          this->do_test(tc.tunnel, tc.ip, 443, [=](bool valid, bool connected, uint32_t cost) {
              this->t_queue.complete(task);
              if (valid) {
                  quality_analyzer::uniq().record_first_package_success(tc.ip, tc.tunnel, cost);
              } else {
                  quality_analyzer::uniq().record_failed(tc.ip, tc.tunnel);
              }
              apm_logger::perf("st-proxy-net-test-stats", {{}}, cost);
          });
      }) {
    for (byte &i : test_request) {
        i = 0b00000000;
    }
    tls_request = new byte[1024];
    tls_request_len = st::utils::base64::decode(TLS_REQUEST_BASE64, tls_request);
}
net_test_manager::~net_test_manager() {
    ic.stop();
    delete iw;
    th.join();
    delete tls_request;
}
net_test_manager &net_test_manager::uniq() {
    static net_test_manager instance;
    return instance;
}
void net_test_manager::tls_handshake_with_socks(const std::string &socks_ip, uint32_t socks_port,
                                                const std::string &test_ip, const net_test_callback &callback) {
    uint32_t begin = time::now();
    string logTag = "net test tls handshake v2 with socks: " + socks_ip + ":" + to_string(socks_port) +
                    " target:" + test_ip + ":443";
    logger::DEBUG << logTag << "start!" << END;
    auto *socket = new tcp::socket(ic);
    tcp::endpoint test_endpoint(make_address_v4(test_ip), 443);
    connect_socks(socket, socks_ip, socks_port, test_endpoint, 1000, [=](bool success) {
        if (success) {
            auto *timer = new deadline_timer(ic);
            timer->expires_from_now(boost::posix_time::milliseconds(TEST_TIME_OUT));
            timer->async_wait([=](boost::system::error_code ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    socket->shutdown(boost::asio::socket_base::shutdown_both, ec);
                    socket->cancel(ec);
                    socket->close(ec);
                }
            });
            auto complete = [=](bool valid, bool connected, uint32_t cost) {
                timer->cancel();
                ic.post([=]() {
                    delete timer;
                    delete socket;
                });
                logger::DEBUG << logTag << "finished!" << END;
                callback(valid, connected, cost);
            };
            auto send_handler = [=](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    pair<uint8_t *, uint32_t> data = st::mem::pmalloc(1024);
                    auto receive_handler = [=](boost::system::error_code ec, std::size_t length) {
                        auto first = *data.first;
                        st::mem::pfree(data);
                        if (!ec) {
                            logger::DEBUG << logTag << "success!" << first << END;
                            complete(true, true, time::now() - begin);
                        } else {
                            logger::WARN << logTag << "receive test response error!"
                                         << string(ec.category().name()) + "/" + ec.message() << length << END;
                            complete(false, true, time::now() - begin);
                        }
                    };
                    socket->async_receive(buffer(data.first, 1), receive_handler);
                } else {
                    complete(false, true, time::now() - begin);
                    logger::WARN << logTag << "send test request error!" << ec.category().name() << ec.message()
                                 << length << END;
                }
            };
            reset_tls_session_id();
            boost::asio::async_write(*socket, buffer(tls_request, tls_request_len),
                                     boost::asio::transfer_at_least(tls_request_len), send_handler);
        } else {
            logger::WARN << logTag << "connect socks failed!" << END;
            callback(false, false, time::now() - begin);
        }
    });
}

void net_test_manager::tls_handshake(uint32_t dist_ip, const std::function<void(bool, bool, uint32_t)> &callback) {
    string logTag = "net test tls handshake direct" + ipv4::ip_to_str(dist_ip) + ":443";
    logger::DEBUG << logTag << "start!" << END;
    tcp::endpoint server_endpoint(make_address_v4(dist_ip), 443);
    auto *socket = new tcp::socket(ic);
    uint32_t begin = time::now();
    auto *timer = new deadline_timer(ic);
    timer->expires_from_now(boost::posix_time::milliseconds(TEST_TIME_OUT));
    timer->async_wait([=](boost::system::error_code ec) {
        socket->shutdown(boost::asio::socket_base::shutdown_both, ec);
        socket->cancel(ec);
        ic.post([=]() {
            boost::system::error_code ec;
            socket->close(ec);
            delete socket;
        });
    });
    socket->open(tcp::v4());
    nat_utils::set_mark(1024, *socket);
    auto complete = [=](bool valid, bool connected, uint32_t cost) {
        delete timer;
        callback(valid, connected, cost);
        logger::DEBUG << logTag << "complete!" << END;
    };
    socket->set_option(tcp::no_delay(true));
#ifdef TCP_FASTOPEN
    using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
    boost::system::error_code ec;
    socket->set_option(fastopen(20), ec);
#endif
    socket->async_connect(server_endpoint, [=](boost::system::error_code ec) {
        if (!ec) {
            auto send_handler = [=](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    pair<uint8_t *, uint32_t> data = st::mem::pmalloc(1024);
                    auto receive_handler = [=](boost::system::error_code ec, std::size_t length) {
                        auto first = *data.first;
                        st::mem::pfree(data);
                        if (!ec) {
                            logger::DEBUG << logTag << "success!" << first << END;
                            complete(true, true, time::now() - begin);
                        } else {
                            complete(false, true, time::now() - begin);
                            if (ec != boost::asio::error::operation_aborted) {
                                logger::WARN << logTag << "receive test response error!"
                                             << string(ec.category().name()) + "/" + ec.message() << length << END;
                            }
                        }
                    };
                    socket->async_read_some(buffer(data.first, data.second), receive_handler);
                } else {
                    complete(false, true, time::now() - begin);
                    logger::WARN << logTag << "send test request error!" << ec.category().name() << ec.message()
                                 << length << END;
                }
            };
            reset_tls_session_id();
            boost::asio::async_write(*socket, buffer(tls_request, tls_request_len),
                                     boost::asio::transfer_at_least(tls_request_len), send_handler);
        } else {
            logger::WARN << logTag << "connect error!" << ec.message() << END;
            complete(false, false, time::now() - begin);
        }
    });
}
void net_test_manager::do_test(stream_tunnel *tunnel, uint32_t dist_ip, uint16_t port,
                               const net_test_callback &callback) {
    net_test_callback complete = [=](bool valid, bool connected, uint32_t cost) {
        apm_logger::perf("st-proxy-net-test-single", {{}}, cost);
        callback(valid, connected, cost);
    };
    if (port == 443) {
        if (tunnel->type == "DIRECT") {
            tls_handshake(dist_ip, complete);
        } else {
            tls_handshake_with_socks(tunnel->ip, tunnel->port, st::utils::ipv4::ip_to_str(dist_ip), complete);
        }
    } else if (port == 80) {
        complete(false, false, 0);
    } else {
        complete(false, false, 0);
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
        socket->cancel(ec);
        socket->close(ec);
        ic.post([=]() { delete socket; });
    });
    socket->open(tcp::v4());
    nat_utils::set_mark(1024, *socket);
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
                                logger::WARN << logTag << "receive test response error!"
                                             << string(ec.category().name()) + "/" + ec.message() << length << END;
                            }
                        }
                    };
                    socket->async_read_some(buffer(data.first, data.second), receive_handler);
                } else {
                    complete(false, true, time::now() - begin);
                    logger::WARN << logTag << "send test request error!" << ec.category().name() << ec.message()
                                 << length << END;
                }
            };
            boost::asio::async_write(*socket, buffer(test_request, TEST_REQUEST_LEN),
                                     boost::asio::transfer_at_least(TEST_REQUEST_LEN), send_handler);
        } else {
            logger::WARN << logTag << "connect error!" << ec.message() << END;
            complete(false, false, time::now() - begin);
        }
    });
}
void net_test_manager::http_random(uint32_t dist_ip, const function<void(bool, bool, uint32_t)> &callback) {
    random_package(dist_ip, 80, callback);
}
void net_test_manager::test(uint32_t dist_ip, uint16_t port, const select_tunnels_tesult &stt) {
    if (port == 443 && stt.size() > 0) {
        int max_score = stt[0].second.first;
        for (const auto &item : stt) {
            auto &record = item.second.second;
            if (item.second.first == max_score) {
                vector<uint16_t> result;
                stream_tunnel *tunnel = item.first;

                for (auto i = record.first_package_failed() + record.first_package_success(); i < record.queue_limit();
                     i++) {
                    test_case tc;
                    tc.ip = dist_ip;
                    tc.port = port;
                    tc.tunnel = tunnel;
                    tc.tunnel_test_index = i;
                    st::task::priority_task<test_case> task(tc, tunnel->type == "DIRECT" ? 0 : 1, tc.key());
                    t_queue.submit(task);
                }
            } else {
                break;
            }
        }
    }
}

void net_test_manager::reset_tls_session_id() {
    std::random_device rd;
    std::default_random_engine gen = std::default_random_engine(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (auto i = 0; i < 32; i++) {
        tls_request[44 + i] = dis(gen);
    }
}

string test_case::key() const {
    return tunnel->id() + "->" + ipv4::ip_to_str(ip) + ":" + to_string(port) + "->" + to_string(tunnel_test_index);
}
