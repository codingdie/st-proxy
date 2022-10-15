//
// Created by codingdie on 2020/9/17.
//

#ifdef linux

#include "quality_analyzer.h"
#include <sys/socket.h>
#endif

#include "nat_utils.h"
#include "proxy_session.h"
#include <algorithm>
#include <map>
#include <vector>

proxy_session::proxy_session(io_context &context)
    : read_counter(), write_counter(), client_sock(context), stage(STAGE::CONNECTING), proxy_sock(context) {
    static std::atomic<uint64_t> id_generator(time::now());
    readProxyBuffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    readClientBuffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    writeProxyBuffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    writeClientBuffer = st::mem::pmalloc(PROXY_BUFFER_SIZE).first;
    id = id_generator++;
}

void proxy_session::start() {
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
    dist_host = st::dns::shm::share().reverse_resolve(dist_end.address().to_v4().to_uint());
    auto realDistPort = st::dns::shm::share().get_real_port(dist_end.address().to_v4().to_uint(), dist_end.port());
    this->dist_end = tcp::endpoint(make_address_v4(this->dist_end.address().to_v4().to_string()), realDistPort.second);
    this->prefer_area = realDistPort.first;
    this->distArea = st::areaip::manager::uniq().get_area(this->dist_end.address().to_v4().to_uint());
    if (this->distArea == "default") {
        logger::WARN << "ip" << st::utils::ipv4::ip_to_str(this->dist_end.address().to_v4().to_uint())
                     << "area not recognized" << END;
    }
    uint64_t begin = time::now();
    select_tunnels();
    apm_logger::perf("st-proxy-select-tunnels", {}, time::now() - begin);

    if (selected_tunnels.empty()) {
        logger::ERROR << idStr() << "cal tunnels empty!" << END;
        shutdown();
        return;
    }
    try_connect();
}

void proxy_session::connect_tunnels(const std::function<void(bool)> &complete_handler) {
    if (try_connect_index < selected_tunnels.size() && this->stage == CONNECTING) {
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
        logger::INFO << idStr() << "connect" << (success ? "success!" : "failed!") << "cost" << connect_cost
                     << try_connect_cost << END;
        if (success) {
            this->nextStage(STAGE::CONNECTED);
            readClient();
            readProxy();
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
    vector<pair<stream_tunnel *, pair<int, proxy::proto::quality_record>>> tunnels;
    uint32_t dist_ip = dist_end.address().to_v4().to_uint();
    for (auto it = st::proxy::config::uniq().tunnels.begin(); it != st::proxy::config::uniq().tunnels.end(); it++) {
        stream_tunnel *tunnel = *it.base();
        int score = 1;
        bool inArea = st::areaip::manager::uniq().is_area_ip(tunnel->proxyAreas, dist_ip);
        if (inArea) {
            score += 10;
        }
        if (tunnel->inWhitelist(dist_ip) || tunnel->inWhitelist(dist_host)) {
            score += 100;
        }
        if (tunnel->area == prefer_area) {
            score += 1000;
        }
        const proxy::proto::quality_record &record = quality_analyzer::uniq().get_record(dist_ip, tunnel);
        if (!quality_analyzer::is_tunnel_valid(record)) {
            score -= 10000;
        }
        tunnels.emplace_back(tunnel, make_pair(score, record));
    }
    std::shuffle(tunnels.begin(), tunnels.end(), std::default_random_engine(time::now()));
    sort(tunnels.begin(), tunnels.end(),
         [=](const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &a,
             const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &b) {
             if (a.second.first == b.second.first) {
                 const proxy::proto::quality_record &record_a = a.second.second;
                 const proxy::proto::quality_record &record_b = b.second.second;
                 if (quality_analyzer::has_enough_data(record_a) && quality_analyzer::has_enough_data(record_b)) {
                     if (record_a.first_package_success() != record_b.first_package_success()) {
                         return record_a.first_package_success() > record_b.first_package_success();
                     } else {
                         if (record_a.first_package_cost() != record_b.first_package_cost()) {
                             return record_a.first_package_cost() < record_b.first_package_cost();
                         }
                     }
                 }
             }
             return a.second.first > b.second.first;
         });
    logger::DEBUG << idStr() << "select_tunnels";
    if (!prefer_area.empty()) {
        logger::DEBUG << "prefer" << prefer_area;
    }
    int i = 0;
    for (auto &it : tunnels) {
        stream_tunnel *tunnel = it.first;
        selected_tunnels.emplace_back(tunnel);
        logger::DEBUG << "[" + to_string(++i) + "]" + tunnel->id() + "[" + to_string(it.second.first) + "/" +
                                 to_string(it.second.second.first_package_success()) + "/" +
                                 to_string(it.second.second.first_package_failed()) + "/" +
                                 to_string(it.second.second.first_package_cost()) + "]";
    }
    logger::DEBUG << END;
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

void proxy_session::proxy_connect(stream_tunnel *tunnel, const std::function<void(bool)> &completeHandler) {
    if (!init_proxy_socks()) {
        completeHandler(false);
        return;
    }
    auto proxyEnd = tcp::endpoint(make_address_v4(tunnel->ip), tunnel->port);
    proxy_sock.async_connect(proxyEnd, [=](boost::system::error_code error) {
        logger::traceId = this->id;
        if (error) {
            completeHandler(false);
        } else {
            writeProxyBuffer[0] = 0x05;
            writeProxyBuffer[1] = 0x01;
            writeProxyBuffer[2] = 0x00;
            writeProxy(3, [=](boost::system::error_code error) {
                if (error) {
                    completeHandler(false);
                    return;
                }
                this->readProxy(2, [=](boost::system::error_code error) {
                    if (!error && readProxyBuffer[0] == 0x05 && readProxyBuffer[1] == 0x00) {
                        writeProxyBuffer[0] = 0x05;
                        writeProxyBuffer[1] = 0x01;
                        writeProxyBuffer[2] = 0x00;
                        writeProxyBuffer[3] = 0x01;
                        auto ipArray = dist_end.address().to_v4().to_bytes();
                        writeProxyBuffer[4] = ipArray[0];
                        writeProxyBuffer[5] = ipArray[1];
                        writeProxyBuffer[6] = ipArray[2];
                        writeProxyBuffer[7] = ipArray[3];
                        uint16_t port = dist_end.port();
                        writeProxyBuffer[8] = (port >> 8) & 0XFF;
                        writeProxyBuffer[9] = port & 0XFF;
                        writeProxy(10, [=](boost::system::error_code error) {
                            if (error) {
                                completeHandler(false);
                                return;
                            }
                            this->readProxy(10, [=](boost::system::error_code error) {
                                if (!error && readProxyBuffer[0] == 0x05 && readProxyBuffer[1] == 0x00) {
                                    completeHandler(true);
                                } else {
                                    completeHandler(false);
                                }
                            });
                        });
                    } else {
                        completeHandler(false);
                    }
                });
            });
        }
    });
}
bool proxy_session::init_proxy_socks() {
    // mac use port to split
    boost::system::error_code error;
    bindLocalPort(client_end, error);
    if (error) {
        logger::ERROR << "init_proxy_socks bindSafePort error!" << error.message() << END;
        return false;
    }
    boost::system::error_code se;
    boost::asio::ip::tcp::acceptor::keep_alive keepAlive(true);
    boost::asio::ip::tcp::no_delay noDelay(true);
    proxy_sock.set_option(keepAlive, se);
    proxy_sock.set_option(noDelay, se);
#ifdef linux
    setMark(1024);
#endif
    return true;
}

#ifdef linux

void proxy_session::setMark(uint32_t mark) {
    int fd = proxy_sock.native_handle();
    int error = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (error == -1) {
        logger::ERROR << "set mark error" << strerror(errno) << logger::ENDL;
    }
}


uint32_t proxy_session::getMark(int fd) {
    uint32_t mark = 0;
    socklen_t len = sizeof(mark);
    int error = getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &len);
    if (error != -1) {
        return mark;
    }
    return -1;
}

#endif

void proxy_session::bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error) {
    boost::system::error_code se;
    proxy_sock.shutdown(boost::asio::socket_base::shutdown_both, se);
    proxy_sock.close(se);
    proxy_sock.cancel(se);
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

void proxy_session::readClient() {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    readClientMax("readClient", PROXY_BUFFER_SIZE, [=](size_t size) {
        copy_byte(this->readClientBuffer, this->writeProxyBuffer, size);
        writeProxy(size);
    });
}

void proxy_session::readClientMax(const string &tag, size_t maxSize,
                                  const std::function<void(size_t size)> &completeHandler) {
    if (!client_sock.is_open()) {
        return;
    }
    client_sock.async_read_some(buffer(readClientBuffer, sizeof(uint8_t) * maxSize),
                                [=](boost::system::error_code error, size_t size) {
                                    logger::traceId = this->id;
                                    if (!error) {
                                        completeHandler(size);
                                    } else {
                                        processError(error, tag);
                                    }
                                });
}


void proxy_session::readProxy() {
    if (!proxy_sock.is_open()) {
        return;
    }
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    proxy_sock.async_read_some(
            buffer(readProxyBuffer, sizeof(uint8_t) * PROXY_BUFFER_SIZE),
            [=](boost::system::error_code error, size_t size) {
                logger::traceId = this->id;
                if (read_counter.total() == 0) {
                    this->first_packet_time = st::utils::time::now() - begin;
                    apm_logger::perf("st-proxy-first-package", dimensions({{"success", to_string(!error)}}),
                                     this->first_packet_time);
                    if (error) {
                        quality_analyzer::uniq().record_failed(dist_end.address().to_v4().to_uint(), connected_tunnel);
                        logger::DEBUG << this->idStr() << "first package failed!" << error.message() << END;
                    } else {
                        quality_analyzer::uniq().record_first_package_success(
                                dist_end.address().to_v4().to_uint(), connected_tunnel, this->first_packet_time);
                    }
                }

                if (!error) {
                    read_counter += size;
                    copy_byte(readProxyBuffer, writeClientBuffer, size);
                    writeClient(size);
                } else {
                    processError(error, "readProxy");
                }
            });
}

void proxy_session::readProxy(size_t size,
                              const std::function<void(boost::system::error_code error)> &completeHandler) {
    if (proxy_sock.is_open()) {
        proxy_sock.async_receive(buffer(readProxyBuffer, sizeof(uint8_t) * size),
                                 [=](boost::system::error_code error, size_t size) { completeHandler(error); });
    }
}
void proxy_session::processError(const boost::system::error_code &error, const string &TAG) {
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
        close(client_sock, [=] {
            close(proxy_sock, [=] {
                apm_logger::perf("st-proxy-shutdown", dimensions({}), time::now() - begin);
                nextStage(DESTROYED);
            });
        });
    }
}
void proxy_session::writeProxy(size_t writeSize) {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    writeProxy("writeProxy", writeSize, [=]() { readClient(); });
}
void proxy_session::writeProxy(const string &tag, size_t writeSize, const std::function<void()> &completeHandler) {
    writeProxy(writeSize, [=](boost::system::error_code error) {
        if (!error) {
            completeHandler();
        } else {
            processError(error, tag);
        }
    });
}
void proxy_session::writeProxy(size_t writeSize,
                               const std::function<void(boost::system::error_code error)> &completeHandler) {
    if (!proxy_sock.is_open()) {
        return;
    }
    size_t len = sizeof(uint8_t) * writeSize;
    boost::asio::async_write(proxy_sock, buffer(writeProxyBuffer, len), boost::asio::transfer_at_least(len),
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

void proxy_session::writeClient(size_t writeSize) {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    writeClient("writeClient", writeSize, [=]() { readProxy(); });
}

void proxy_session::writeClient(const string &tag, size_t writeSize, const std::function<void()> &completeHandler) {
    size_t len = sizeof(uint8_t) * writeSize;
    if (!client_sock.is_open()) {
        return;
    }
    boost::asio::async_write(client_sock, buffer(writeClientBuffer, len), boost::asio::transfer_at_least(len),
                             [=](boost::system::error_code error, size_t size) {
                                 logger::traceId = this->id;
                                 if (error) {
                                     processError(error, tag);
                                 } else {
                                     completeHandler();
                                 }
                             });
}


proxy_session::~proxy_session() {
    logger::traceId = id;
    logger::INFO << idStr() << "disconnect" << transmit_log() << END;
    mem::pfree(readProxyBuffer, PROXY_BUFFER_SIZE);
    mem::pfree(readClientBuffer, PROXY_BUFFER_SIZE);
    mem::pfree(writeProxyBuffer, PROXY_BUFFER_SIZE);
    mem::pfree(writeClientBuffer, PROXY_BUFFER_SIZE);
}

string proxy_session::idStr() {
    return asio::addr_str(client_end) + "->" + asio::addr_str(dist_end) +
           (connected_tunnel != nullptr ? ("->" + connected_tunnel->id()) : "");
}

string proxy_session::transmit_log() const {
    const uint64_t val = time::now() - this->begin;
    return "live:" + to_string(val) + ", read:" + to_string(this->read_counter.total()) +
           ", write:" + to_string(this->write_counter.total());
}
bool proxy_session::nextStage(proxy_session::STAGE nextStage) {
    stageLock.lock();
    bool result = false;
    if (this->stage < nextStage) {
        this->stage = nextStage;
        result = true;
    }
    stageLock.unlock();
    return result;
}
bool proxy_session::is_transmitting() {
    uint64_t soTimeout = st::proxy::config::uniq().so_timeout;
    auto now = time::now();
    bool noWrite = !write_counter.is_start() ? (now - begin >= soTimeout)
                                             : (now - write_counter.get_last_record_time() >= soTimeout);
    bool noRead = !read_counter.is_start() ? (now - begin >= soTimeout)
                                           : (now - read_counter.get_last_record_time() >= soTimeout);
    return !(noWrite && noRead);
}

bool proxy_session::is_connect_timeout() {
    uint64_t conTimeout = st::proxy::config::uniq().connect_timeout;
    auto now = time::now();
    return stage.load() == proxy_session::STAGE::CONNECTING && (now - begin >= conTimeout);
}


bool proxy_session::is_closed() { return stage == proxy_session::STAGE::DESTROYED; }

unordered_map<string, string> proxy_session::dimensions(unordered_map<string, string> &&dimensions) {
    unordered_map<string, string> result = {
            {"tunnel", connected_tunnel != nullptr ? connected_tunnel->id() : ""},
            {"tunnelType", connected_tunnel != nullptr ? connected_tunnel->type : ""},
            {"tunnelArea", connected_tunnel != nullptr ? connected_tunnel->area : ""},
            {"tunnelIndex", connected_tunnel != nullptr ? to_string(try_connect_index) : "-1"},
            {"clientIP", client_end.address().to_string()},
            {"distHost", dist_host},
            {"distArea", distArea},
            {"distIP", dist_end.address().to_string()},
            {"distEndPort", to_string(dist_end.port())}};
    result.insert(dimensions.begin(), dimensions.end());
    return result;
}
