//
// Created by codingdie on 10/16/22.
//

#include "net_test_manager.h"
#include "nat_utils.h"
#include "quality_analyzer.h"
#include <boost/asio/ssl.hpp>
net_test_manager::net_test_manager()
    : ic(), iw(new io_context::work(ic)), schedule_timer(ic), generate_key_timer(ic), th([this]() { ic.run(); }) {
    for (byte &i : test_request) {
        i = 0b00000000;
    }
    schedule_dispatch_test();
    schedule_generate_key();
}

void net_test_manager::schedule_dispatch_test() {
    ic.post([this]() {
        if (key_count > 0) {
            apm_logger::perf("st-proxy-net-test-stats", {{}}, {{"heap", test_queue.size()}});
            test_case t_case = poll_one_test();
            if (t_case.ip != 0) {
                auto result = quality_analyzer::uniq().select_tunnels(t_case.ip, "");
                auto need_test_count = quality_analyzer::uniq().cal_need_test_count(result);
                if (need_test_count > 0) {
                    logger::DEBUG << "net test begin" << t_case.key() << "count" << need_test_count << END;
                    test_re(t_case, need_test_count, 0, [=](uint32_t valid) {
                        test_queue.erase(t_case.key());
                        running_test--;
                        logger::DEBUG << "net test end" << t_case.key() << "valid" << valid << END;
                    });
                } else {
                    test_queue.erase(t_case.key());
                    running_test--;
                    logger::WARN << "net test ignored" << t_case.key() << END;
                }
            }
        }
    });
    schedule_timer.expires_from_now(boost::posix_time::milliseconds(100));
    schedule_timer.async_wait([this](error_code ec) { schedule_dispatch_test(); });
}
test_case net_test_manager::poll_one_test() {
    test_case t_case(0, 0);
    if (test_queue.empty() || running_test == test_queue.size() || running_test >= TEST_CONCURENT) {
        return t_case;
    }
    t_case.timestamp = time::now();
    vector<pair<string, test_case>> tests(test_queue.begin(), test_queue.end());
    sort(tests.begin(), tests.end(), [](const pair<string, test_case> &a, const pair<string, test_case> &b) {
        if (a.second.priority != b.second.priority) {
            return a.second.priority > b.second.priority;
        }
        return a.second.timestamp > b.second.timestamp;
    });
    for (auto i = 0; i < TEST_CONCURENT && i < tests.size(); i++) {
        if (tests[i].second.status == 0) {
            string key = tests[i].first;
            test_queue.at(key).status = 1;
            running_test++;
            return test_queue.at(key);
        }
    }
    return t_case;
}
void net_test_manager::schedule_generate_key() {
    generate_key_timer.expires_from_now(boost::posix_time::milliseconds(100));
    generate_key_timer.async_wait([this](error_code ec) {
        key_count += TEST_QPS / 10.0;
        key_count = min(TEST_QPS * 1.0, (double) key_count);
        schedule_generate_key();
    });
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
void net_test_manager::tls_handshake_v2(uint32_t dist_ip, const function<void(bool, bool, uint32_t)> &callback) {
    string logTag = "net test tls handshake v2" + ipv4::ip_to_str(dist_ip) + ":443";
    tcp::endpoint server_endpoint(make_address_v4(dist_ip), 443);
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
    nat_utils::set_mark(1025, *socket);
    auto complete = [=](bool valid, bool connected, uint32_t cost) {
        delete timer;
        callback(valid, connected, cost);
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
            boost::asio::async_write(*socket, buffer(TLS_REQUEST, TLS_REQUEST_LEN),
                                     boost::asio::transfer_at_least(TLS_REQUEST_LEN), send_handler);
        } else {
            logger::WARN << logTag << "connect error!" << ec.message() << END;
            complete(true, false, time::now() - begin);
        }
    });
}
void net_test_manager::do_test(uint32_t dist_ip, uint16_t port, const net_test_callback &callback) {
    if (port == 443) {
        tls_handshake_v2(dist_ip, callback);
    } else if (port == 80) {
        callback(false, false, true);
    } else {
        callback(false, false, true);
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
            complete(true, false, time::now() - begin);
        }
    });
}
void net_test_manager::http_random(uint32_t dist_ip, const function<void(bool, bool, uint32_t)> &callback) {
    random_package(dist_ip, 80, callback);
}
void net_test_manager::test(uint32_t dist_ip, uint16_t port, uint16_t priority) {
    if (port == 443) {
        ic.post([=]() {
            test_case tc(dist_ip, port);
            tc.priority = priority;
            if (test_queue.emplace(tc.key(), tc).second) {
                logger::DEBUG << "add net test" << ipv4::ip_to_str(dist_ip) + ":" + to_string(port) << END;
            } else {
                test_case &old_tc = test_queue.at(tc.key());
                if (old_tc.status == 0) {
                    tc.priority = priority;
                    old_tc.timestamp = time::now();
                }
            }
        });
    }
}

void net_test_manager::test_re(const test_case &tc, uint16_t count, uint32_t valid_count,
                               const std::function<void(uint32_t valid)> &callback) {
    if (count <= 0) {
        callback(valid_count);
    } else {
        acquire_key([=]() {
            auto begin = time::now();
            do_test(tc.ip, tc.port, [=](bool valid, bool connected, uint32_t cost) {
                apm_logger::perf("st-proxy-net-test", {{"test_case", tc.key()}}, time::now() - begin);
                test_re(tc, count - 1, valid_count + (valid ? 1 : 0), callback);
            });
        });
    }
}
void net_test_manager::acquire_key(const function<void()> &callback) {
    if (key_count > 0) {
        key_count = key_count - 1;
        ic.post(callback);
    } else {
        auto *timer = new deadline_timer(ic);
        timer->expires_from_now(boost::posix_time::milliseconds(50));
        timer->async_wait([=](boost::system::error_code ec) {
            delete timer;
            acquire_key(callback);
        });
    }
}
test_case::test_case(uint32_t ip, uint16_t port) : ip(ip), port(port), status(0), timestamp(time::now()) {}
bool test_case::operator<(const test_case &rhs) const {
    if (ip < rhs.ip) return true;
    if (rhs.ip < ip) return false;
    return port < rhs.port;
}
string test_case::key() const { return ipv4::ip_to_str(ip) + ":" + to_string(port); }
