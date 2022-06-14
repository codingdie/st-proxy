//
// Created by codingdie on 2020/9/17.
//

#ifdef linux

#include <sys/socket.h>

#endif

#include "nat_utils.h"
#include "proxy_session.h"
#include <algorithm>
#include <map>
#include <vector>

proxy_session::proxy_session(io_context &context)
    : read_counter(), write_counter(), client_sock(context), stage(STAGE::CONNECTING), proxy_sock(context) {
    readProxyBuffer = st::mem::pmalloc(bufferSize).first;
    readClientBuffer = st::mem::pmalloc(bufferSize).first;
    writeProxyBuffer = st::mem::pmalloc(bufferSize).first;
    writeClientBuffer = st::mem::pmalloc(bufferSize).first;
}

void proxy_session::start() {
    begin = time::now();
    boost::system::error_code error;
    clientEnd = client_sock.remote_endpoint(error);
    if (error) {
        logger::ERROR << "get client addr failed!" << error.message() << END;
        shutdown();
        return;
    }
    this->distEnd = nat_utils::INSTANCE.getProxyAddr(client_sock);
    if (this->distEnd.address().to_v4().to_uint() == 0) {
        logger::ERROR << "get dist addr failed!" << END;
        shutdown();
        return;
    }
    distHost = st::dns::shm::share().reverse_resolve(distEnd.address().to_v4().to_uint());
    auto realDistPort = st::dns::shm::share().get_real_port(distEnd.address().to_v4().to_uint(), distEnd.port());
    this->distEnd = tcp::endpoint(make_address_v4(this->distEnd.address().to_v4().to_string()), realDistPort.second);
    this->preferArea = realDistPort.first;
    this->distArea = st::areaip::manager::uniq().get_area(this->distEnd.address().to_v4().to_uint());
    if (this->distArea == "default") {
        logger::WARN << "ip" << st::utils::ipv4::ip_to_str(this->distEnd.address().to_v4().to_uint())
                     << "area not recognized" << END;
    }

    selectTunnels();
    if (targetTunnels.empty()) {
        logger::ERROR << idStr() << "cal tunnels empty!" << END;
        shutdown();
        return;
    }
    try_connect();
}

void proxy_session::connect_tunnels(std::function<void(bool)> completeHandler) {
    if (tryConnectIndex < targetTunnels.size() && this->stage == CONNECTING) {
        stream_tunnel *tunnel = targetTunnels[tryConnectIndex];
        auto complete = [=](bool success) {
            if (success) {
                this->connected_tunnel = tunnel;
                completeHandler(true);
            } else {
                logger::ERROR << idStr() << "connect" << tunnel->toString() << "failed!" << END;
                tryConnectIndex++;
                connect_tunnels(completeHandler);
            }
        };
        if (tunnel->type == "DIRECT") {
            directConnect(tunnel, complete);
        } else {
            proxyConnect(tunnel, complete);
        }
    } else {
        completeHandler(false);
    }
}
void proxy_session::try_connect() {
    connect_tunnels([=](bool success) {
        logger::traceId = id;
        uint64_t connectCost = time::now() - begin;
        logger::INFO << idStr() << "connect" << (success ? "success!" : "failed!") << "cost" << connectCost << END;
        if (success) {
            this->nextStage(STAGE::CONNECTED);
            readClient();
            readProxy();
        } else {
            shutdown();
        }
        apm_logger::perf("st-proxy-connect", dimensions({{"success", to_string(success)}}), connectCost);
    });
}

void proxy_session::selectTunnels() {
    vector<pair<stream_tunnel *, int>> tunnels;
    uint32_t distIP = distEnd.address().to_v4().to_uint();
    for (auto it = st::proxy::config::INSTANCE.tunnels.begin(); it != st::proxy::config::INSTANCE.tunnels.end(); it++) {
        stream_tunnel *tunnel = *it.base();

        int score = 1;
        bool inArea = st::areaip::manager::uniq().is_area_ip(tunnel->proxyAreas, distIP);
        if (inArea) {
            score += 1000;
        }
        if (tunnel->inWhitelist(distIP) || tunnel->inWhitelist(distHost)) {
            score += 10000;
        }
        if (tunnel->area == preferArea) {
            score += 1000000;
        }
        tunnels.emplace_back(tunnel, score);
    }
    std::shuffle(tunnels.begin(), tunnels.end(), std::default_random_engine(time::now()));
    sort(tunnels.begin(), tunnels.end(),
         [=](const pair<stream_tunnel *, int> &a, const pair<stream_tunnel *, int> &b) { return a.second > b.second; });
    logger::INFO << idStr() << "selectTunnels";
    if (!preferArea.empty()) {
        logger::INFO << "prefer" << preferArea;
    }
    int i = 0;
    for (auto it = tunnels.begin(); it != tunnels.end(); it++) {
        stream_tunnel *tunnel = it->first;
        targetTunnels.emplace_back(tunnel);
        logger::INFO << "[" + to_string(++i) + "]" + tunnel->toString() + "[" + to_string(it->second) + "]";
    }
    logger::INFO << END;
}
void proxy_session::directConnect(stream_tunnel *tunnel, std::function<void(bool)> completeHandler) {
    if (!initProxySocks()) {
        completeHandler(false);
        return;
    }
    proxy_sock.async_connect(distEnd, [=](boost::system::error_code error) {
        logger::traceId = this->id;
        if (error) {
            completeHandler(false);
        } else {
            completeHandler(true);
        }
    });
}

void proxy_session::proxyConnect(stream_tunnel *tunnel, std::function<void(bool)> completeHandler) {
    if (!initProxySocks()) {
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
                        auto ipArray = distEnd.address().to_v4().to_bytes();
                        writeProxyBuffer[4] = ipArray[0];
                        writeProxyBuffer[5] = ipArray[1];
                        writeProxyBuffer[6] = ipArray[2];
                        writeProxyBuffer[7] = ipArray[3];
                        uint16_t port = distEnd.port();
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
bool proxy_session::initProxySocks() {
    // mac use port to split
    boost::system::error_code error;
    bindLocalPort(clientEnd, error);
    if (error) {
        logger::ERROR << "initProxySocks bindSafePort error!" << error.message() << END;
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
    readClientMax("readClient", bufferSize, [=](size_t size) {
        copy_byte(this->readClientBuffer, this->writeProxyBuffer, size);
        writeProxy(size);
    });
}

void proxy_session::readClientMax(const string &tag, size_t maxSize, std::function<void(size_t size)> completeHandler) {
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
            buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize), [=](boost::system::error_code error, size_t size) {
                logger::traceId = this->id;
                if (read_counter.total() == 0) {
                    this->first_packet_time = st::utils::time::now() - begin;
                    apm_logger::perf("st-proxy-first-package", dimensions({{"success", to_string(!error)}}),
                                     this->first_packet_time);
                    if (error) {
                        logger::DEBUG << this->idStr() << "first package failed!" << error.message() << END;
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

void proxy_session::readProxy(size_t size, std::function<void(boost::system::error_code error)> completeHandler) {
    if (proxy_sock.is_open()) {
        proxy_sock.async_receive(buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize),
                                 [=](boost::system::error_code error, size_t size) { completeHandler(error); });
    }
}
void proxy_session::processError(const boost::system::error_code &error, const string &TAG) {
    bool isEOF = error.category() == error::misc_category && error == error::misc_errors::eof;
    bool isCancled = error == error::operation_aborted;
    if (!isCancled && !isEOF) {
        logger::ERROR << TAG << error.message() << END;
    }
    shutdown();
}
void proxy_session::close(tcp::socket &socks, std::function<void()> completeHandler) {
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
void proxy_session::writeProxy(const string &tag, size_t writeSize, std::function<void()> completeHandler) {
    writeProxy(writeSize, [=](boost::system::error_code error) {
        if (!error) {
            completeHandler();
        } else {
            processError(error, tag);
        }
    });
}
void proxy_session::writeProxy(size_t writeSize, std::function<void(boost::system::error_code error)> completeHandler) {
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

void proxy_session::writeClient(const string &tag, size_t writeSize, std::function<void()> completeHandler) {
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
    mem::pfree(readProxyBuffer, bufferSize);
    mem::pfree(readClientBuffer, bufferSize);
    mem::pfree(writeProxyBuffer, bufferSize);
    mem::pfree(writeClientBuffer, bufferSize);
}

string proxy_session::idStr() {
    return asio::addr_str(clientEnd) + "->" + asio::addr_str(distEnd) +
           (connected_tunnel != nullptr ? ("->" + connected_tunnel->toString()) : "");
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
    uint64_t soTimeout = st::proxy::config::INSTANCE.so_timeout;
    auto now = time::now();
    bool noWrite = !write_counter.is_start() ? (now - begin >= soTimeout)
                                             : (now - write_counter.get_last_record_time() >= soTimeout);
    bool noRead = !read_counter.is_start() ? (now - begin >= soTimeout)
                                           : (now - read_counter.get_last_record_time() >= soTimeout);
    return !(noWrite && noRead);
}

bool proxy_session::is_connect_timeout() {
    uint64_t conTimeout = st::proxy::config::INSTANCE.connect_timeout;
    auto now = time::now();
    return stage.load() == proxy_session::STAGE::CONNECTING ? (now - begin >= conTimeout) : false;
}


bool proxy_session::is_closed() { return stage == proxy_session::STAGE::DESTROYED; }

unordered_map<string, string> proxy_session::dimensions(unordered_map<string, string> &&dimensions) {
    unordered_map<string, string> result = {
            {"tunnel", connected_tunnel != nullptr ? connected_tunnel->toString() : ""},
            {"tunnelType", connected_tunnel != nullptr ? connected_tunnel->type : ""},
            {"tunnelArea", connected_tunnel != nullptr ? connected_tunnel->area : ""},
            {"tunnelIndex", connected_tunnel != nullptr ? to_string(connectingTunnelIndex) : "-1"},
            {"clientIP", clientEnd.address().to_string()},
            {"distHost", distHost},
            {"distArea", distArea},
            {"distIP", distEnd.address().to_string()},
            {"distEndPort", to_string(distEnd.port())}};
    result.insert(dimensions.begin(), dimensions.end());
    return result;
}
