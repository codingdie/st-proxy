//
// Created by codingdie on 2020/9/17.
//

#ifndef ST_PROXY_TCPSESSION_H
#define ST_PROXY_TCPSESSION_H

#include "Common.h"

class TCPSession {
public:
    enum STAGE { CONNECTING, CONNECTED, DETROYING, DETROYED };

    static const uint32_t bufferSize = 1024;

    TCPSession(uint64_t id, tcp::socket &sock, st::proxy::Config &config);

    virtual ~TCPSession();

    uint64_t id;
    uint16_t port = 0;
    uint64_t begin = 0;
    uint64_t lastReadTunnelTime = 0;
    uint64_t readTunnelTime = 0;
    uint64_t readTunnelSize = 0;
    uint64_t lastWriteTunnelTime = 0;
    uint64_t writeTunnelTime = 0;
    uint64_t writeTunnelSize = 0;
    STStreamTunnel *connectedTunnel = nullptr;
    STAGE stage = CONNECTING;
    uint64_t tryConnectIndex = -1;

    void start();

    tcp::endpoint distEnd;

    string toString();

    string transmit() const;

    void shutdown();

    void tryConnect();

private:
    tcp::socket clientSock;
    tcp::socket proxySock;
    st::proxy::Config &config;
    vector<STStreamTunnel *> targetTunnels;
    tcp::endpoint clientEnd;
    byte readClientBuffer[bufferSize];
    byte writeProxyBuffer[bufferSize];
    byte writeClientBuffer[bufferSize];
    byte readProxyBuffer[bufferSize];
    io_context::strand upStrand;
    io_context::strand downStrand;
    mutex stageLock;
    int connectingTunnelIndex = 0;
    void readClientMax(const string &tag, size_t maxSize,
                       std::function<void(size_t size)> completeHandler);
    void readClient();

    void writeClient(size_t size);
    void writeClient(const string &tag, size_t size, std::function<void()> completeHandler);

    void readProxy();
    void readProxy(size_t size,
                   std::function<void(boost::system::error_code error)> completeHandler);
    void writeProxy(size_t size);
    void writeProxy(const string &tag, size_t size, std::function<void()> completeHandler);
    void writeProxy(size_t size,
                    std::function<void(boost::system::error_code error)> completeHandler);

    void connetTunnels(std::function<void(bool)> completeHandler);
    void directConnect(STStreamTunnel *tunnel, std::function<void(bool)> completeHandler);

    void proxyConnect(STStreamTunnel *tunnel, std::function<void(bool)> completeHandler);

    void selectTunnels();


    void closeClient(std::function<void()> completeHandler);
    void closeServer(std::function<void()> completeHandler);


    void bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error);

    void processError(const boost::system::error_code &error, const string &TAG);

    void copyOption();

    bool initProxySocks();

    bool nextStage(TCPSession::STAGE nextStage);

#ifdef linux

    void setMark();

#endif
};

#endif// ST_PROXY_TCPSESSION_H
