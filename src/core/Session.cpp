//
// Created by codingdie on 2020/9/17.
//

#ifdef linux

#include <sys/socket.h>

#endif

#include "AreaIpManager.h"
#include "NATUtils.h"
#include "Session.h"
#include "SessionManager.h"
#include <set>
#include <vector>
Session::Session(uint64_t id, tcp::socket &sock, st::proxy::Config &config)
    : id(id), begin(time::now()), clientSock(std::move(sock)), config(config), proxySock((io_context &) clientSock.get_executor().context()),
      upStrand((io_context &) clientSock.get_executor().context()), downStrand((io_context &) clientSock.get_executor().context()),
      readTunnelCounter(), writeTunnelCounter() {
    readProxyBuffer = pmalloc(bufferSize);
    readClientBuffer = pmalloc(bufferSize);
    writeProxyBuffer = pmalloc(bufferSize);
    writeClientBuffer = pmalloc(bufferSize);
}

void Session::start() {
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

    if (this->distEnd.address().to_v4().to_uint() == 0) {
        Logger::ERROR << "get dist addr illegel!" << END;
        shutdown();
        return;
    }
    selectTunnels();
    if (targetTunnels.empty()) {
        Logger::ERROR << idStr() << "cal tunnels empty!" << END;
        shutdown();
        return;
    }
    tryConnect();
}

void Session::connetTunnels(std::function<void(bool)> completeHandler) {
    if (tryConnectIndex < targetTunnels.size()) {
        auto complete = [=](bool success) {
            if (success) {
                this->connectedTunnel = targetTunnels[tryConnectIndex];
                completeHandler(true);
            } else {
                Logger::ERROR << idStr() << "connect" << targetTunnels[tryConnectIndex]->toString() << "failed! cost" << time::now() - begin << END;
                tryConnectIndex++;
                connetTunnels(completeHandler);
            }
        };
        StreamTunnel *tunnel = targetTunnels[tryConnectIndex];
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
    tryConnectIndex++;

    connetTunnels([=](bool success) {
        Logger::traceId = id;
        Logger::INFO << idStr() << "connect" << (success ? "success!" : "failed!") << "cost" << time::now() - begin << END;
        if (success) {
            readClient();
            readProxy();
            this->nextStage(STAGE::CONNECTED);
        } else {
            shutdown();
        }
    });
}

void Session::selectTunnels() {
    vector<pair<StreamTunnel *, int>> tunnels;
    uint32_t distIP = distEnd.address().to_v4().to_uint();
    for (auto it = config.tunnels.begin(); it != config.tunnels.end(); it++) {
        StreamTunnel *tunnel = *it.base();
        int score = tunnel->priority;
        if (tunnel->onlyAreaIp) {
            if (!AreaIpManager::isAreaIP(tunnel->area, distIP)) {
                continue;
            }
        }
        if (tunnel->whitelistIPs.find(distIP) != tunnel->whitelistIPs.end()) {
            score += 10000;
        };
        tunnels.emplace_back(make_pair(tunnel, score));
    }
    sort(tunnels.begin(), tunnels.end(), [=](pair<StreamTunnel *, int> &a, pair<StreamTunnel *, int> &b) {
        if (a.second != b.second) {
            return a.second > b.second;
        } else {
            int ra = rand();
            return abs(ra % 2) == 0;
        }
    });
    Logger::INFO << idStr() << "selectTunnels:";
    int i = 0;
    for (auto &pairv : tunnels) {
        StreamTunnel *tunnel = pairv.first;
        targetTunnels.emplace_back(tunnel);
        Logger::INFO << "[" + to_string(++i) + "]" + tunnel->toString() + "[" + to_string(pairv.second) + "]";
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
    setMark();
#endif
    return true;
}

#ifdef linux

void Session::setMark() {
    int fd = proxySock.native_handle();
    int mark = 1024;
    int error = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (error == -1) {
        Logger::ERROR << "set mark error" << strerror(errno) << Logger::ENDL;
    }
}

#endif

void Session::bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error) {
    boost::system::error_code se;
    proxySock.shutdown(boost::asio::socket_base::shutdown_both, se);
    proxySock.release(se);
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
    readClientMax("readClient", bufferSize, [=](size_t size) {
        copyByte(this->readClientBuffer, this->writeProxyBuffer, size);
        writeProxy(size);
    });
}
void Session::readClientMax(const string &tag, size_t maxSize, std::function<void(size_t size)> completeHandler) {
    clientSock.async_read_some(buffer(readClientBuffer, sizeof(uint8_t) * maxSize), upStrand.wrap([=](boost::system::error_code error, size_t size) {
        Logger::traceId = this->id;
        if (!error) {
            completeHandler(size);
        } else {
            processError(error, tag);
        }
    }));
}


void Session::readProxy() {
    long begin = time::now();
    proxySock.async_read_some(buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize),
                              downStrand.wrap([=](boost::system::error_code error, size_t size) {
                                  Logger::traceId = this->id;
                                  if (!error) {
                                      readTunnelCounter += size;
                                      copyByte(readProxyBuffer, writeClientBuffer, size);
                                      writeClient(size);
                                  } else {
                                      processError(error, "readProxy");
                                  }
                              }));
}
void Session::readProxy(size_t size, std::function<void(boost::system::error_code error)> completeHandler) {
    proxySock.async_receive(buffer(readProxyBuffer, sizeof(uint8_t) * bufferSize),
                            downStrand.wrap([=](boost::system::error_code error, size_t size) { completeHandler(error); }));
}
void Session::processError(const boost::system::error_code &error, const string &TAG) {
    bool isEOF = error.category() == error::misc_category && error == error::misc_errors::eof;
    bool isCancled = error == error::operation_aborted;
    if (!isCancled && !isEOF) {
        Logger::ERROR << TAG << error.message() << END;
    }
    shutdown();
}


void Session::closeClient(std::function<void()> completeHandler) {
    boost::system::error_code ec;
    clientSock.shutdown(boost::asio::socket_base::shutdown_both, ec);
    clientSock.cancel(ec);
    clientSock.close(ec);
    completeHandler();
}
void Session::closeServer(std::function<void()> completeHandler) {
    boost::system::error_code ec;
    proxySock.shutdown(boost::asio::socket_base::shutdown_both, ec);
    proxySock.cancel(ec);
    proxySock.close(ec);
    completeHandler();
}

void Session::shutdown() {
    if (nextStage(DETROYING)) {
        closeClient([=] { closeServer([=] { nextStage(DETROYED); }); });
    }
}
void Session::writeProxy(size_t writeSize) {
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
    long begin = time::now();
    size_t len = sizeof(uint8_t) * writeSize;
    boost::asio::async_write(proxySock, buffer(writeProxyBuffer, len), boost::asio::transfer_at_least(len),
                             upStrand.wrap([=](boost::system::error_code error, size_t size) {
                                 Logger::traceId = this->id;
                                 if (!error) {
                                     writeTunnelCounter += size;
                                 }
                                 completeHandler(error);
                             }));
}

void Session::writeClient(size_t writeSize) {
    writeClient("writeClient", writeSize, [=]() { readProxy(); });
}

void Session::writeClient(const string &tag, size_t writeSize, std::function<void()> completeHandler) {
    size_t len = sizeof(uint8_t) * writeSize;
    boost::asio::async_write(clientSock, buffer(writeClientBuffer, len), boost::asio::transfer_at_least(len),
                             downStrand.wrap([=](boost::system::error_code error, size_t size) {
                                 Logger::traceId = this->id;
                                 if (error) {
                                     processError(error, tag);
                                 } else {
                                     completeHandler();
                                 }
                             }));
}


Session::~Session() {
    Logger::traceId = id;
    Logger::INFO << idStr() << "disconnect" << transmitLog() << END;
    pfree(readProxyBuffer, bufferSize);
    pfree(readClientBuffer, bufferSize);
    pfree(writeProxyBuffer, bufferSize);
    pfree(writeClientBuffer, bufferSize);
}

string Session::idStr() {
    return asio::addrStr(clientEnd) + "->" + asio::addrStr(distEnd) + (connectedTunnel != nullptr ? +"->" + connectedTunnel->toString() : "");
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
    bool noWrite = !writeTunnelCounter.isStart() ? (now - begin >= soTimeout) : (now - writeTunnelCounter.getLastRecordTime() >= soTimeout);
    bool noRead = !readTunnelCounter.isStart() ? (now - begin >= soTimeout) : (now - readTunnelCounter.getLastRecordTime() >= soTimeout);
    return !(noWrite && noRead);
}

bool Session::isConnectTimeout() {
    uint64_t conTimeout = st::proxy::Config::INSTANCE.connectTimeout;
    auto now = time::now();
    return stage == Session::STAGE::CONNECTING ? (now - begin >= conTimeout) : false;
}


bool Session::isClosed() { return stage == Session::STAGE::DETROYED; }
