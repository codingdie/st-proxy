//
// Created by codingdie on 2020/9/17.
//

#ifndef ST_PROXY_SESSION_H
#define ST_PROXY_SESSION_H

#include "Common.h"

class Session {
public:
    enum STAGE { CONNECTING, CONNECTED, DETROYING, DETROYED };

    static const uint32_t bufferSize = 2048;

    uint64_t id;
    uint16_t port = 0;
    IntervalCounter readTunnelCounter;
    IntervalCounter writeTunnelCounter;

    StreamTunnel *connectedTunnel = nullptr;
    STAGE stage = CONNECTING;

    Session(uint64_t id, tcp::socket &sock, st::proxy::Config &config);

    virtual ~Session();

    void start();

    string idStr();

    string transmitLog() const;

    std::pair<uint64_t, uint64_t> transmit() const;

    void shutdown();

    void tryConnect();
    bool isTransmitting();
    bool isConnectTimeout();
    bool isClosed();
private:
    tcp::socket clientSock;
    tcp::socket proxySock;
    st::proxy::Config &config;
    vector<StreamTunnel *> targetTunnels;
    tcp::endpoint clientEnd;
    byte *readClientBuffer;
    byte *writeProxyBuffer;
    byte *writeClientBuffer;
    byte *readProxyBuffer;
    io_context::strand upStrand;
    io_context::strand downStrand;
    mutex stageLock;
    int connectingTunnelIndex = 0;
    uint64_t tryConnectIndex = -1;
    tcp::endpoint distEnd;
    uint64_t begin = 0;
    void readClientMax(const string &tag, size_t maxSize, std::function<void(size_t size)> completeHandler);
    void readClient();

    void writeClient(size_t size);
    void writeClient(const string &tag, size_t size, std::function<void()> completeHandler);

    void readProxy();
    void readProxy(size_t size, std::function<void(boost::system::error_code error)> completeHandler);
    void writeProxy(size_t size);
    void writeProxy(const string &tag, size_t size, std::function<void()> completeHandler);
    void writeProxy(size_t size, std::function<void(boost::system::error_code error)> completeHandler);

    void connetTunnels(std::function<void(bool)> completeHandler);

    void directConnect(StreamTunnel *tunnel, std::function<void(bool)> completeHandler);

    void proxyConnect(StreamTunnel *tunnel, std::function<void(bool)> completeHandler);

    void selectTunnels();

    void closeClient(std::function<void()> completeHandler);

    void closeServer(std::function<void()> completeHandler);


    void bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error);

    void processError(const boost::system::error_code &error, const string &TAG);

    void copyOption();

    bool initProxySocks();

    bool nextStage(Session::STAGE nextStage);

#ifdef linux

    void setMark();

#endif
};

#endif// ST_PROXY_SESSION_H
