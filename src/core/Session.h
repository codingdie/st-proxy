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
    tcp::endpoint distEnd;
    tcp::endpoint clientEnd;
    string distHost = "";
    std::atomic<STAGE> stage;
    tcp::socket clientSock;
    tcp::socket proxySock;
    Session(io_context &context);

    virtual ~Session();

    void start();

    string idStr();

    string transmitLog() const;


    void shutdown();

    void tryConnect();

    bool isTransmitting();

    bool isConnectTimeout();

    bool isClosed();

    unordered_map<string, string> dimensions(unordered_map<string, string> &&dimensions);

private:
    vector<StreamTunnel *> targetTunnels;
    byte *readClientBuffer;
    byte *writeProxyBuffer;
    byte *writeClientBuffer;
    byte *readProxyBuffer;
    mutex stageLock;
    int connectingTunnelIndex = 0;
    uint64_t tryConnectIndex = 0;
    uint64_t begin = 0;
    string preferArea = "";
    string distArea = "";


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

    void close(tcp::socket &socks, std::function<void()> completeHandler);

    void bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error);

    void processError(const boost::system::error_code &error, const string &TAG);

    void copyOption();

    bool initProxySocks();

    bool nextStage(Session::STAGE nextStage);

#ifdef linux

    void setMark(uint32_t mark);
    uint32_t getMark(int fd);

#endif
};

#endif// ST_PROXY_SESSION_H
