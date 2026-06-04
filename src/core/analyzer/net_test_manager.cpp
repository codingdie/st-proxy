//
// Created by codingdie on 10/16/22.
//

#include "net_test_manager.h"
#include "command/dns_command.h"
#include "config.h"
#include "nat_utils.h"
#include <boost/asio/ssl.hpp>

namespace {
net_test_manager *g_net_test_manager_instance = nullptr;
}

net_test_manager::net_test_manager()
    : ic(), iw(new io_context::work(ic)), th([this]() { ic.run(); }),
      t_queue("st-proxy-net-test", st::proxy::config::uniq().net_test_config.max_qps,
              st::proxy::config::uniq().net_test_config.max_running,
              [this](const st::task::priority_task<test_case> &task) {
                  const test_case &tc = task.get_input();
                  this->do_test(tc.proxy, tc.ip, 443, [=](bool valid, bool connected, uint32_t cost) {
                      this->t_queue.complete(task);
                      if (valid) {
                          quality_analyzer::uniq().record_first_package_success(tc.ip, tc.tunnel_id, cost);
                      } else {
                          quality_analyzer::uniq().record_failed(tc.ip, tc.tunnel_id);
                      }
                  });
              }) {
    g_net_test_manager_instance = this;
    for (byte &i : test_request) {
        i = 0b00000000;
    }
    tls_request = new byte[1024];
    tls_request_len = st::utils::base64::decode(TLS_REQUEST_BASE64, tls_request);
}
void net_test_manager::stop() {
    if (stopped.exchange(true)) {
        return;
    }
    if (health_check_timer != nullptr) {
        boost::system::error_code ec;
        health_check_timer->cancel(ec);
    }
    t_queue.stop();
    ic.stop();
    delete iw;
    iw = nullptr;
    if (th.joinable()) {
        th.join();
    }
}
net_test_manager::~net_test_manager() {
    stop();
    g_net_test_manager_instance = nullptr;
    delete[] tls_request;
    delete health_check_timer;
    health_check_timer = nullptr;
}
net_test_manager &net_test_manager::uniq() {
    static net_test_manager instance;
    return instance;
}
net_test_manager *net_test_manager::instance_or_null() { return g_net_test_manager_instance; }
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
            timer->expires_from_now(boost::posix_time::milliseconds(st::proxy::config::uniq().net_test_config.timeout));
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
                            if (ec != boost::asio::error::operation_aborted) {
                                logger::WARN << logTag << "receive test response error!"
                                             << string(ec.category().name()) + "/" + ec.message() << length << END;
                            }
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
    string logTag = "net test tls handshake direct " + ipv4::ip_to_str(dist_ip) + ":443";
    logger::DEBUG << logTag << "start!" << END;
    tcp::endpoint server_endpoint(make_address_v4(dist_ip), 443);
    auto *socket = new tcp::socket(ic);
    uint32_t begin = time::now();
    auto *timer = new deadline_timer(ic);
    timer->expires_from_now(boost::posix_time::milliseconds(st::proxy::config::uniq().net_test_config.timeout));
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
            if (ec != boost::asio::error::operation_aborted) {
                logger::WARN << logTag << "connect error!" << ec.message() << END;
            }
            complete(false, false, time::now() - begin);
        }
    });
}
void net_test_manager::do_test(socks5_proxy proxy, uint32_t dist_ip, uint16_t port, const net_test_callback &callback) {
    net_test_callback complete = [=](bool valid, bool connected, uint32_t cost) {
        apm_logger::perf("st-proxy-net-test-single", {{}}, cost);
        callback(valid, connected, cost);
    };
    if (port == 443) {
        if (proxy.ip.empty() || proxy.port == 0) {
            tls_handshake(dist_ip, complete);
        } else {
            tls_handshake_with_socks(proxy.ip, proxy.port, st::utils::ipv4::ip_to_str(dist_ip), complete);
        }
    } else {
        complete(false, false, 0);
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
void net_test_manager::submit(const st::task::priority_task<test_case> &t) { t_queue.submit(t); }
vector<task::priority_task<test_case>> net_test_manager::current_all_test() { return t_queue.all(); }

string test_case::key() const {
    return tunnel_id + "->" + ipv4::ip_to_str(ip) + ":" + to_string(port) + "->" + to_string(tunnel_test_index);
}

std::pair<std::string, uint16_t> net_test_manager::parse_check_url(const std::string &url) {
    std::string s = url;
    uint16_t port = 443;
    if (s.find("https://") == 0) {
        s = s.substr(8);
        port = 443;
    } else if (s.find("http://") == 0) {
        s = s.substr(7);
        port = 80;
    }
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        s = s.substr(0, slash);
    }
    auto colon = s.find(':');
    if (colon != std::string::npos) {
        port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
        s = s.substr(0, colon);
    }
    return std::make_pair(s, port);
}

void net_test_manager::check_tunnel_health(stream_tunnel *tunnel,
                                           const std::function<void(bool, uint32_t)> &callback) {
    auto host_port = parse_check_url(tunnel->http_check_url);
    const std::string &host = host_port.first;
    uint16_t port = host_port.second;

    if (port != 443) {
        logger::WARN << "tunnel" << tunnel->id() << "http_check_url port != 443, skip" << END;
        callback(false, 0);
        return;
    }

    auto ips = st::utils::dns::query(st::proxy::config::uniq().dns, host);
    if (ips.empty()) {
        ips = st::utils::dns::query(host);
    }
    if (ips.empty()) {
        logger::WARN << "tunnel" << tunnel->id() << "resolve" << host << "failed" << END;
        callback(false, 0);
        return;
    }
    uint32_t target_ip = ips[0];

    auto net_callback = [=](bool valid, bool /*connected*/, uint32_t cost) {
        callback(valid, cost);
    };

    if (tunnel->type == "DIRECT") {
        tls_handshake(target_ip, net_callback);
    } else {
        tls_handshake_with_socks(tunnel->ip, tunnel->port,
                                 st::utils::ipv4::ip_to_str(target_ip), net_callback);
    }
}

void net_test_manager::run_health_check_round() {
    auto &tunnels = st::proxy::config::uniq().tunnels;
    for (auto *tunnel : tunnels) {
        check_tunnel_health(tunnel, [tunnel](bool valid, uint32_t cost) {
            tunnel->last_check_time.store(time::now());
            tunnel->last_check_cost.store(cost);
            if (valid) {
                tunnel->consecutive_failures.store(0);
                if (tunnel->health_status.load() != HEALTH_UP) {
                    logger::INFO << "tunnel" << tunnel->id() << "health UP cost" << cost << END;
                }
                tunnel->health_status.store(HEALTH_UP);
            } else {
                uint32_t failures = tunnel->consecutive_failures.fetch_add(1) + 1;
                if (failures >= TUNNEL_HEALTH_DOWN_THRESHOLD) {
                    if (tunnel->health_status.load() != HEALTH_DOWN) {
                        logger::WARN << "tunnel" << tunnel->id() << "health DOWN after"
                                     << failures << "consecutive failures" << END;
                    }
                    tunnel->health_status.store(HEALTH_DOWN);
                }
            }
        });
    }
}

void net_test_manager::schedule_health_check() {
    health_check_timer->expires_from_now(
            boost::posix_time::milliseconds(static_cast<long>(TUNNEL_HEALTH_CHECK_INTERVAL_MS)));
    health_check_timer->async_wait([this](boost::system::error_code ec) {
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }
        run_health_check_round();
        schedule_health_check();
    });
}

void net_test_manager::start_tunnel_health_check() {
    if (health_check_timer != nullptr) {
        return;
    }
    health_check_timer = new boost::asio::deadline_timer(ic);
    ic.post([this]() {
        run_health_check_round();
        schedule_health_check();
    });
}
