//
// Created by codingdie on 2020/9/17.
//

#ifdef linux

#include "quality_analyzer.h"
#endif

#include "command/dns_command.h"
#include "nat_utils.h"
#include "net_test_manager.h"
#include "proxy_session.h"
#include "virtual_port_manager.h"
#include <map>
#include <utility>
#include <vector>
proxy_session::proxy_session(io_context &context, string tag)
    : read_counter(), write_counter(), client_sock(context), tag(std::move(tag)), stage(STAGE::CONNECTING),
      proxy_sock(context) {
    static std::atomic<uint64_t> id_generator(time::now());
    in_buffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    out_buffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    id = id_generator++;
}

void proxy_session::start() {
    logger::traceId = id;
    begin = time::now();
    boost::system::error_code error;
    client_end = client_sock.remote_endpoint(error);
    if (error) {
        logger::ERROR << "get client addr failed!" << error.message() << END;
        shutdown();
        return;
    }
    this->dist_end = nat_utils::INSTANCE.getProxyAddr(client_sock);
    if (this->dist_end.address().to_v4().to_uint() == 0) {
        logger::ERROR << "get dist addr failed!" << END;
        shutdown();
        return;
    }
    dist_hosts = st::command::dns::reverse_resolve(dist_end.address().to_v4().to_uint());
    if (dist_hosts.empty()) {
        dist_hosts.emplace_back(dist_end.address().to_v4().to_string());
    }
    auto realDistPort =
            virtual_port_manager::uniq().get_real_port(dist_end.address().to_v4().to_uint(), dist_end.port());
    this->dist_end = tcp::endpoint(make_address_v4(this->dist_end.address().to_v4().to_string()), realDistPort.second);
    this->prefer_area = realDistPort.first;
    this->distArea = st::areaip::manager::uniq().get_area(this->dist_end.address().to_v4().to_uint());
    if (this->distArea == "default") {
        logger::WARN << "ip" << st::utils::ipv4::ip_to_str(this->dist_end.address().to_v4().to_uint())
                     << "area not recognized" << END;
    }
    select_tunnels();
    if (selected_tunnels.empty()) {
        logger::ERROR << idStr() << "cal tunnels empty!" << END;
        shutdown();
        return;
    }
    try_connect();
}

void proxy_session::connect_tunnels(const std::function<void(bool)> &complete_handler) {
    if (try_connect_index < 1 && this->stage == CONNECTING) {
        stream_tunnel *tunnel = selected_tunnels[try_connect_index];
        auto complete = [=](bool success) {
            if (success) {
                this->connected_tunnel = tunnel;
                complete_handler(true);
            } else {
                logger::ERROR << idStr() << "connect" << tunnel->id() << "failed!" << END;
                try_connect_index++;
                connect_tunnels(complete_handler);
            }
        };
        if (tunnel->type == "DIRECT") {
            direct_connect(complete);
        } else {
            proxy_connect(tunnel, complete);
        }
    } else {
        complete_handler(false);
    }
}
void proxy_session::try_connect() {
    uint64_t real_begin = time::now();
    connect_tunnels([=](bool success) {
        logger::traceId = id;
        uint64_t connect_cost = time::now() - begin;
        uint64_t try_connect_cost = time::now() - real_begin;
        logger::DEBUG << idStr() << "connect" << (success ? "success!" : "failed!") << "cost" << connect_cost
                      << try_connect_cost << END;
        if (success) {
            this->nextStage(STAGE::CONNECTED);
            read_client();
            read_proxy();
        } else {
            for (auto i = 0; i <= try_connect_index && i < selected_tunnels.size(); i++) {
                quality_analyzer::uniq().record_failed(dist_end.address().to_v4().to_uint(), selected_tunnels[i]);
            }
            shutdown();
        }
        apm_logger::perf("st-proxy-connect", dimensions({{"success", to_string(success)}}), connect_cost);
        apm_logger::perf("st-proxy-try-connect", dimensions({{"success", to_string(success)}}), try_connect_cost);
    });
}

void proxy_session::select_tunnels() {
    uint32_t dist_ip = dist_end.address().to_v4().to_uint();
    auto select_result = quality_analyzer::uniq().select_tunnels(dist_ip, dist_hosts, prefer_area);
    int need_test_count = quality_analyzer::uniq().cal_need_test_count(select_result);
    if (need_test_count > 0 && !is_net_test()) {
        net_test_manager::uniq().test(dist_ip, dist_end.port(), select_result[0].first->type == "DIRECT" ? 0 : 1);
    }
    for (const auto &it : select_result) {
        stream_tunnel *tunnel = it.first;
        selected_tunnels.emplace_back(tunnel);
    }
}
void proxy_session::direct_connect(const std::function<void(bool)> &completeHandler) {
    if (!init_proxy_socks()) {
        completeHandler(false);
        return;
    }
    proxy_sock.async_connect(dist_end, [=](boost::system::error_code error) {
        logger::traceId = this->id;
        if (error) {
            completeHandler(false);
        } else {
            completeHandler(true);
        }
    });
}

void proxy_session::proxy_connect(stream_tunnel *tunnel, const std::function<void(bool)> &complete) {
    if (!init_proxy_socks()) {
        complete(false);
        return;
    }
    auto proxyEnd = tcp::endpoint(make_address_v4(tunnel->ip), tunnel->port);
    proxy_sock.async_connect(proxyEnd, [=](boost::system::error_code error) {
        logger::traceId = this->id;
        if (error) {
            complete(false);
        } else {
            out_buffer[0] = 0x05;
            out_buffer[1] = 0x01;
            out_buffer[2] = 0x00;
            write_proxy(3, [=](boost::system::error_code error) {
                if (error) {
                    complete(false);
                    return;
                }
                this->read_proxy(2, [=](boost::system::error_code error) {
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
                        write_proxy(10, [=](boost::system::error_code error) {
                            if (error) {
                                complete(false);
                                return;
                            }
                            this->read_proxy(10, [=](boost::system::error_code error) {
                                if (!error && in_buffer[0] == 0x05 && in_buffer[1] == 0x00) {
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
            });
        }
    });
}
bool proxy_session::init_proxy_socks() {
    // mac use port to split
    boost::system::error_code error;
    bind_local_port(client_end, error);
    if (error) {
        logger::ERROR << "init proxy socks bind local port error!" << error.message() << END;
        return false;
    }
    boost::system::error_code se;
    proxy_sock.set_option(boost::asio::ip::tcp::acceptor::keep_alive(true), se);
    proxy_sock.set_option(boost::asio::ip::tcp::no_delay(true), se);
#ifdef linux
    nat_utils::set_mark(1024, proxy_sock);
#endif
    return true;
}

#ifdef linux


#endif

void proxy_session::bind_local_port(basic_endpoint<tcp> &endpoint, boost::system::error_code &error) {
    boost::system::error_code se;
    if (proxy_sock.is_open()) {
        proxy_sock.shutdown(boost::asio::socket_base::shutdown_both, se);
        proxy_sock.cancel(se);
        proxy_sock.close(se);
    }
    proxy_sock.open(tcp::v4());
#ifdef __APPLE__
    proxy_sock.bind(tcp::endpoint(endpoint.address(), session_manager::share().guess_unused_port()), error);
    int i = 1;
    while (error && i <= 1000) {
        proxy_sock.bind(tcp::endpoint(endpoint.address(), session_manager::share().guess_unused_port()), error);
        i++;
    }
#endif
}

void proxy_session::read_client() {
    read_client_max("read_client", PROXY_BUFFER_SIZE, [=](size_t size) { write_proxy(size); });
}

void proxy_session::read_client_max(const string &tag, size_t maxSize,
                                    const std::function<void(size_t size)> &completeHandler) {
    if (!client_sock.is_open()) {
        shutdown();
        return;
    }
    client_sock.async_read_some(buffer(out_buffer, sizeof(uint8_t) * maxSize),
                                [=](boost::system::error_code error, size_t size) {
                                    logger::traceId = this->id;
                                    if (!error) {
                                        completeHandler(size);
                                    } else {
                                        process_error(error, tag);
                                    }
                                });
}


void proxy_session::read_proxy() {
    if (!proxy_sock.is_open()) {
        shutdown();
        return;
    }
    proxy_sock.async_read_some(buffer(in_buffer, sizeof(uint8_t) * PROXY_BUFFER_SIZE), [=](boost::system::error_code
                                                                                                   error,
                                                                                           size_t size) {
        logger::traceId = this->id;
        auto first_packet_time = st::utils::time::now() - begin;

        if (read_counter.total() == 0) {
            apm_logger::perf("st-proxy-first-package", dimensions({{"success", to_string(!error)}}), first_packet_time);
            if (error) {
                if (!is_net_test() || dist_end.port() == 80 || dist_end.port() == 443) {
                    quality_analyzer::uniq().record_failed(dist_end.address().to_v4().to_uint(), connected_tunnel);
                }
                logger::DEBUG << this->idStr() << "first package failed!" << error.message() << END;
            } else {
                quality_analyzer::uniq().record_first_package_success(dist_end.address().to_v4().to_uint(),
                                                                      connected_tunnel, first_packet_time);
            }
        }

        if (!error) {
            read_counter += size;
            write_client(size);
        } else {
            process_error(error, "read_proxy");
        }
    });
}

void proxy_session::read_proxy(size_t size, const std::function<void(boost::system::error_code error)> &complete) {
    if (proxy_sock.is_open()) {
        proxy_sock.async_receive(buffer(in_buffer, sizeof(uint8_t) * size),
                                 [=](boost::system::error_code error, size_t size) { complete(error); });
    } else {
        complete(boost::asio::error::make_error_code(boost::asio::error::connection_aborted));
    }
}
void proxy_session::process_error(const boost::system::error_code &error, const string &TAG) {
    bool isEOF = error.category() == error::misc_category && error == error::misc_errors::eof;
    bool isCancel = error == error::operation_aborted;
    if (!isCancel && !isEOF) {
        logger::ERROR << TAG << error.message() << END;
    }
    shutdown();
}
void proxy_session::close(tcp::socket &socks, const std::function<void()> &completeHandler) {
    io_context &ctx = (io_context &) socks.get_executor().context();
    boost::system::error_code ec;
    socks.shutdown(boost::asio::socket_base::shutdown_both, ec);
    ctx.post([=, &socks]() {
        boost::system::error_code ec;
        socks.shutdown(boost::asio::socket_base::shutdown_both, ec);
        socks.cancel(ec);
        socks.close(ec);
        completeHandler();
    });
}

void proxy_session::shutdown() {
    if (nextStage(DESTROYING)) {
        close(client_sock, [=] { close(proxy_sock, [=] { nextStage(DESTROYED); }); });
    }
}
void proxy_session::write_proxy(size_t writeSize) {
    write_proxy("write_proxy", writeSize, [=]() { read_client(); });
}
void proxy_session::write_proxy(const string &tag, size_t writeSize, const std::function<void()> &completeHandler) {
    write_proxy(writeSize, [=](boost::system::error_code error) {
        if (!error) {
            completeHandler();
        } else {
            process_error(error, tag);
        }
    });
}
void proxy_session::write_proxy(size_t writeSize,
                                const std::function<void(boost::system::error_code error)> &completeHandler) {
    if (!proxy_sock.is_open()) {
        completeHandler(boost::asio::error::make_error_code(boost::asio::error::connection_aborted));
        return;
    }
    size_t len = sizeof(uint8_t) * writeSize;
    boost::asio::async_write(proxy_sock, buffer(out_buffer, len), boost::asio::transfer_at_least(len),
                             [=](boost::system::error_code error, size_t size) {
                                 logger::traceId = this->id;
                                 if (!error) {
                                     if (connected_tunnel != nullptr) {
                                         write_counter += size;
                                     }
                                 }
                                 completeHandler(error);
                             });
}

void proxy_session::write_client(size_t writeSize) {
    write_client("write_client", writeSize, [=]() { read_proxy(); });
}

void proxy_session::write_client(const string &tag, size_t writeSize, const std::function<void()> &completeHandler) {
    size_t len = sizeof(uint8_t) * writeSize;
    if (!client_sock.is_open()) {
        shutdown();
        return;
    }
    boost::asio::async_write(client_sock, buffer(in_buffer, len), boost::asio::transfer_at_least(len),
                             [=](boost::system::error_code error, size_t size) {
                                 logger::traceId = this->id;
                                 if (error) {
                                     process_error(error, tag);
                                 } else {
                                     completeHandler();
                                 }
                             });
}


proxy_session::~proxy_session() {
    logger::traceId = id;
    logger::INFO << idStr() << "disconnect" << transmit_log() << END;
    mem::pfree(in_buffer, PROXY_BUFFER_SIZE);
    mem::pfree(out_buffer, PROXY_BUFFER_SIZE);
}

string proxy_session::idStr() {
    return tag + "->" + (prefer_area.empty() ? "" : prefer_area + "->") + asio::addr_str(client_end) + "->" +
           asio::addr_str(dist_end) + (connected_tunnel != nullptr ? ("->" + connected_tunnel->id()) : "");
}

string proxy_session::transmit_log() const {
    const uint64_t val = time::now() - this->begin;
    return "live:" + to_string(val) + ", read:" + to_string(this->read_counter.total()) +
           ", write:" + to_string(this->write_counter.total());
}
bool proxy_session::nextStage(proxy_session::STAGE nextStage) {
    stageLock.lock();
    bool result = false;
    if (this->stage <= nextStage) {
        this->stage = nextStage;
        result = true;
    }
    stageLock.unlock();
    return result;
}
bool proxy_session::is_transmitting() {
    uint64_t soTimeout = st::proxy::config::uniq().so_timeout;
    if (is_net_test()) {
        soTimeout = 3000L;
    }
    auto now = time::now();
    bool noWrite = !write_counter.is_start() ? (now - begin >= soTimeout)
                                             : (now - write_counter.get_last_record_time() >= soTimeout);
    bool noRead = !read_counter.is_start() ? (now - begin >= soTimeout)
                                           : (now - read_counter.get_last_record_time() >= soTimeout);
    return !(noWrite && noRead) && client_sock.is_open() && proxy_sock.is_open();
}

bool proxy_session::is_connect_timeout() {
    uint64_t conTimeout = st::proxy::config::uniq().connect_timeout;
    auto now = time::now();
    return stage.load() == proxy_session::STAGE::CONNECTING && (now - begin >= conTimeout);
}


bool proxy_session::is_closed() { return stage == proxy_session::STAGE::DESTROYED; }

unordered_map<string, string> proxy_session::dimensions(unordered_map<string, string> &&dimensions) {
    unordered_map<string, string> result = {{"tunnel", connected_tunnel != nullptr ? connected_tunnel->id() : ""},
                                            {"tunnel_type", connected_tunnel != nullptr ? connected_tunnel->type : ""},
                                            {"tunnel_area", connected_tunnel != nullptr ? connected_tunnel->area : ""},
                                            {"client_ip", client_end.address().to_string()},
                                            {"dist_host", dist_hosts[0]},
                                            {"dist_area", distArea},
                                            {"tag", tag},
                                            {"prefer_area", prefer_area},
                                            {"dist_ip", dist_end.address().to_string()},
                                            {"dist_end_port", to_string(dist_end.port())}};
    result.insert(dimensions.begin(), dimensions.end());
    return result;
}
bool proxy_session::is_net_test() const { return "net_test" == tag; }
