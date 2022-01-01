//
// Created by codingdie on 2020/9/17.
//

#ifdef linux

#include <sys/socket.h>

#endif

#include "NATUtils.h"
#include "Session.h"
#include "SessionManager.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>

Session::Session(io_context &context)
    : stage(STAGE::CONNECTING), id(id), clientSock(context), proxySock(context), readTunnelCounter(),
      writeTunnelCounter() {
    readProxyBuffer = st::mem::pmalloc(bufferSize).first;
    readClientBuffer = st::mem::pmalloc(bufferSize).first;
    writeProxyBuffer = st::mem::pmalloc(bufferSize).first;
    writeClientBuffer = st::mem::pmalloc(bufferSize).first;
}

void Session::start() {
    begin = time::now();
    boost::system::error_code error;
    clientEnd = clientSock.remote_endpoint(error);
    if (error) {
        Logger::ERROR << "get client addr failed!" << error.message() << END;
        shutdown();
        return;
    }
    this->distEnd = NATUtils::INSTANCE.getProxyAddr(clientSock);
    if (this->distEnd.address().to_v4().to_uint() == 0) {
        Logger::ERROR << "get dist addr failed!" << END;
        shutdown();
        return;
    }
    distHost = st::dns::SHM::read().query(distEnd.address().to_v4().to_uint());
    auto realDistPort = st::dns::SHM::read().getRealPort(distEnd.address().to_v4().to_uint(), distEnd.port());
    this->distEnd = tcp::endpoint(make_address_v4(this->distEnd.address().to_v4().to_string()), realDistPort.second);
    this->preferArea = realDistPort.first;
    selectTunnels();
    if (targetTunnels.empty()) {
        Logger::ERROR << idStr() << "cal tunnels empty!" << END;
        shutdown();
        return;
    }
    tryConnect();
}

void Session::connetTunnels(std::function<void(bool)> completeHandler) {
    if (tryConnectIndex < targetTunnels.size() && this->stage == CONNECTING) {
        StreamTunnel *tunnel = targetTunnels[tryConnectIndex];
        auto complete = [=](bool success) {
            if (success) {
                this->connectedTunnel = tunnel;
                completeHandler(true);
            } else {
                Logger::ERROR << idStr() << "connect" << tunnel->toString() << "failed!" << END;
                tryConnectIndex++;
                connetTunnels(completeHandler);
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
void Session::tryConnect() {
    connetTunnels([=](bool success) {
        Logger::traceId = id;
        uint64_t connectCost = time::now() - begin;
        Logger::INFO << idStr() << "connect" << (success ? "success!" : "failed!") << "cost" << connectCost << END;
        if (success) {
            this->nextStage(STAGE::CONNECTED);
            readClient();
            readProxy();
        } else {
            shutdown();
        }
        APMLogger::perf("st-proxy-connect", dimensions({{"success", to_string(success)}}), connectCost);
    });
}

void Session::selectTunnels() {
    vector<pair<StreamTunnel *, int>> tunnels;
    uint32_t distIP = distEnd.address().to_v4().to_uint();
    for (auto it = st::proxy::Config::INSTANCE.tunnels.begin(); it != st::proxy::Config::INSTANCE.tunnels.end(); it++) {
        StreamTunnel *tunnel = *it.base();

        int score = 1;
        if (!tunnel->area.empty()) {
            bool inArea = st::areaip::isAreaIP(tunnel->area, distIP);
            if (inArea) {
                score += 1000;
            }
        }
        if (tunnel->whitelistIPs.find(distIP) != tunnel->whitelistIPs.end()) {
            score += 10000;
        };
        if (tunnel->area.compare(preferArea) == 0) {
            score += 1000000;
        }
        tunnels.push_back(make_pair(tunnel, score));
    }
    std::shuffle(tunnels.begin(), tunnels.end(), std::default_random_engine(time::now()));
    sort(tunnels.begin(), tunnels.end(),
         [=](const pair<StreamTunnel *, int> &a, const pair<StreamTunnel *, int> &b) { return a.second > b.second; });
    Logger::INFO << idStr() << "prefer" << preferArea << "selectTunnels";
    int i = 0;
    for (auto it = tunnels.begin(); it != tunnels.end(); it++) {
        StreamTunnel *tunnel = it->first;
        targetTunnels.emplace_back(tunnel);
        Logger::INFO << "[" + to_string(++i) + "]" + tunnel->toString() + "[" + to_string(it->second) + "]";
    }
    Logger::INFO << END;
}
void Session::directConnect(StreamTunnel *tunnel, std::function<void(bool)> completeHandler) {
    if (!initProxySocks()) {
        completeHandler(false);
        return;
    }
    proxySock.async_connect(distEnd, [=](boost::system::error_code error) {
        Logger::traceId = this->id;
        if (error) {
            completeHandler(false);
        } else {
            completeHandler(true);
        }
    });
}

void Session::proxyConnect(StreamTunnel *tunnel, std::function<void(bool)> completeHandler) {
    if (!initProxySocks()) {
        completeHandler(false);
        return;
    }
    auto proxyEnd = tcp::endpoint(make_address_v4(tunnel->ip), tunnel->port);
    proxySock.async_connect(proxyEnd, [=](boost::system::error_code error) {
        Logger::traceId = this->id;
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
bool Session::initProxySocks() {
    // mac use port to split
    boost::system::error_code error;
    bindLocalPort(clientEnd, error);
    if (error) {
        Logger::ERROR << "initProxySocks bindSafePort error!" << error.message() << END;
        return false;
    }
    boost::system::error_code se;
    boost::asio::ip::tcp::acceptor::keep_alive keepAlive(true);
    boost::asio::ip::tcp::no_delay noDelay(true);
    proxySock.set_option(keepAlive, se);
    proxySock.set_option(noDelay, se);
#ifdef linux
    setMark(1024);
#endif
    return true;
}

#ifdef linux

void Session::setMark(uint32_t mark) {
    int fd = proxySock.native_handle();
    int error = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (error == -1) {
        Logger::ERROR << "set mark error" << strerror(errno) << Logger::ENDL;
    }
}


uint32_t Session::getMark(int fd) {
    uint32_t mark = 0;
    socklen_t len = sizeof(mark);
    int error = getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &len);
    if (error != -1) {
        return mark;
    }
    return -1;
}

#endif

void Session::bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error) {
    boost::system::error_code se;
    proxySock.shutdown(boost::asio::socket_base::shutdown_both, se);
    proxySock.close(se);
    proxySock.cancel(se);
    proxySock.open(tcp::v4());
#ifdef __APPLE__
    proxySock.bind(tcp::endpoint(endpoint.address(), SessionManager::INSTANCE->guessUnusedSafePort()), error);
    int i = 1;
    while (error && i <= 1000) {
        proxySock.bind(tcp::endpoint(endpoint.address(), SessionManager::INSTANCE->guessUnusedSafePort()), error);
        i++;
    }
#endif
}

void Session::readClient() {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    readClientMax("readClient", bufferSize, [=](size_t size) {
        copyByte(this->readClientBuffer, this->writeProxyBuffer, size);
        writeProxy(size);
    });
}

void Session::readClientMax(const string &tag, size_t maxSize, std::function<void(size_t size)> completeHandler) {
    if (!clientSock.is_open()) {
        return;
    }
    clientSock.async_read_some(buffer(readClientBuffer, sizeof(uint8_t) * maxSize),
                               [=](boost::system::error_code error, size_t size) {
                                   Logger::traceId = this->id;
                                   if (!error) {
                                       completeHandler(size);
                                   } else {
                                       processError(error, tag);
                                   }
                               });
}


void Session::readProxy() {
    if (!proxySock.is_open()) {
        return;
    }
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    proxySock.async_read_some(
            buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize), [=](boost::system::error_code error, size_t size) {
                Logger::traceId = this->id;
                if (readTunnelCounter.totalCount == 0) {
                    APMLogger::perf("st-proxy-first-package", dimensions({{"success", to_string(!error)}}),
                                    st::utils::time::now() - begin);
                }
                if (!error) {
                    if (connectedTunnel != nullptr) {
                        readTunnelCounter += size;
                    }
                    copyByte(readProxyBuffer, writeClientBuffer, size);
                    writeClient(size);
                } else {
                    processError(error, "readProxy");
                }
            });
}

void Session::readProxy(size_t size, std::function<void(boost::system::error_code error)> completeHandler) {
    if (proxySock.is_open()) {
        proxySock.async_receive(buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize),
                                [=](boost::system::error_code error, size_t size) { completeHandler(error); });
    }
}
void Session::processError(const boost::system::error_code &error, const string &TAG) {
    bool isEOF = error.category() == error::misc_category && error == error::misc_errors::eof;
    bool isCancled = error == error::operation_aborted;
    if (!isCancled && !isEOF) {
        Logger::ERROR << TAG << error.message() << END;
    }
    shutdown();
}
void Session::close(tcp::socket &socks, std::function<void()> completeHandler) {
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

void Session::shutdown() {
    if (nextStage(DETROYING)) {
        close(clientSock, [=] {
            close(proxySock, [=] {
                APMLogger::perf("st-proxy-shutdown", dimensions({}), time::now() - begin);
                nextStage(DETROYED);
            });
        });
    }
}
void Session::writeProxy(size_t writeSize) {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    writeProxy("writeProxy", writeSize, [=]() { readClient(); });
}
void Session::writeProxy(const string &tag, size_t writeSize, std::function<void()> completeHandler) {
    writeProxy(writeSize, [=](boost::system::error_code error) {
        if (!error) {
            completeHandler();
        } else {
            processError(error, tag);
        }
    });
}
void Session::writeProxy(size_t writeSize, std::function<void(boost::system::error_code error)> completeHandler) {
    if (!proxySock.is_open()) {
        return;
    }
    size_t len = sizeof(uint8_t) * writeSize;
    boost::asio::async_write(proxySock, buffer(writeProxyBuffer, len), boost::asio::transfer_at_least(len),
                             [=](boost::system::error_code error, size_t size) {
                                 Logger::traceId = this->id;
                                 if (!error) {
                                     if (connectedTunnel != nullptr) {
                                         writeTunnelCounter += size;
                                     }
                                 }
                                 completeHandler(error);
                             });
}

void Session::writeClient(size_t writeSize) {
    if (stage.load() != STAGE::CONNECTED) {
        return;
    }
    writeClient("writeClient", writeSize, [=]() { readProxy(); });
}

void Session::writeClient(const string &tag, size_t writeSize, std::function<void()> completeHandler) {
    size_t len = sizeof(uint8_t) * writeSize;
    if (!clientSock.is_open()) {
        return;
    }
    boost::asio::async_write(clientSock, buffer(writeClientBuffer, len), boost::asio::transfer_at_least(len),
                             [=](boost::system::error_code error, size_t size) {
                                 Logger::traceId = this->id;
                                 if (error) {
                                     processError(error, tag);
                                 } else {
                                     completeHandler();
                                 }
                             });
}


Session::~Session() {
    Logger::traceId = id;
    Logger::INFO << idStr() << "disconnect" << transmitLog() << END;
    mem::pfree(readProxyBuffer, bufferSize);
    mem::pfree(readClientBuffer, bufferSize);
    mem::pfree(writeProxyBuffer, bufferSize);
    mem::pfree(writeClientBuffer, bufferSize);
}

string Session::idStr() {
    return asio::addrStr(clientEnd) + "->" + asio::addrStr(distEnd) +
           (connectedTunnel != nullptr ? ("->" + connectedTunnel->toString()) : "");
}

string Session::transmitLog() const {
    const uint64_t val = time::now() - this->begin;
    return "live:" + to_string(val) + ", read:" + to_string(this->readTunnelCounter.total().second) +
           ", write:" + to_string(this->writeTunnelCounter.total().second);
}
std::pair<uint64_t, uint64_t> Session::transmit() const {}

bool Session::nextStage(Session::STAGE nextStage) {
    stageLock.lock();
    bool result = false;
    if (this->stage < nextStage) {
        this->stage = nextStage;
        result = true;
    }
    stageLock.unlock();
    return result;
}
bool Session::isTransmitting() {
    uint64_t soTimeout = st::proxy::Config::INSTANCE.soTimeout;
    auto now = time::now();
    bool noWrite = !writeTunnelCounter.isStart() ? (now - begin >= soTimeout)
                                                 : (now - writeTunnelCounter.getLastRecordTime() >= soTimeout);
    bool noRead = !readTunnelCounter.isStart() ? (now - begin >= soTimeout)
                                               : (now - readTunnelCounter.getLastRecordTime() >= soTimeout);
    return !(noWrite && noRead);
}

bool Session::isConnectTimeout() {
    uint64_t conTimeout = st::proxy::Config::INSTANCE.connectTimeout;
    auto now = time::now();
    return stage.load() == Session::STAGE::CONNECTING ? (now - begin >= conTimeout) : false;
}


bool Session::isClosed() { return stage == Session::STAGE::DETROYED; }

unordered_map<string, string> Session::dimensions(unordered_map<string, string> &&dimensions) {
    unordered_map<string, string> result = {
            {"tunnel", connectedTunnel != nullptr ? connectedTunnel->toString() : ""},
            {"tunnelType", connectedTunnel != nullptr ? connectedTunnel->type : ""},
            {"tunnelArea", connectedTunnel != nullptr ? connectedTunnel->area : ""},
            {"tunnelIndex", connectedTunnel != nullptr ? to_string(connectingTunnelIndex) : "-1"},
            {"clientIP", clientEnd.address().to_string()},
            {"distHost", distHost},
            {"distEndPort", to_string(distEnd.port())}};
    result.insert(dimensions.begin(), dimensions.end());
    return result;
}
