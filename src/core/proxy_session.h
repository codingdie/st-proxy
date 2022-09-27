//
// Created by codingdie on 2020/9/17.
//

#ifndef ST_PROXY_PROXY_SESSION_H
#define ST_PROXY_PROXY_SESSION_H

#include "common.h"

class proxy_session {
public:
    enum STAGE { CONNECTING, CONNECTED, DESTROYING, DESTROYED };
    static const uint32_t bufferSize = 2048;
    uint64_t id;
    uint16_t port = 0;
    st::utils::counters::interval read_counter;
    st::utils::counters::interval write_counter;
    stream_tunnel *connected_tunnel = nullptr;
    tcp::socket client_sock;
    uint64_t first_packet_time = 0;

    explicit proxy_session(io_context &context);

    virtual ~proxy_session();

    void start();

    string idStr();

    string transmit_log() const;

    void shutdown();

    void try_connect();

    bool is_transmitting();

    bool is_connect_timeout();

    bool is_closed();

    unordered_map<string, string> dimensions(unordered_map<string, string> &&dimensions);

private:
    vector<stream_tunnel *> targetTunnels;
    byte *readClientBuffer;
    byte *writeProxyBuffer;
    byte *writeClientBuffer;
    byte *readProxyBuffer;
    mutex stageLock;
    int connectingTunnelIndex = 0;
    uint64_t tryConnectIndex = 0;
    uint64_t begin = 0;
    string preferArea;
    string distArea;
    tcp::endpoint dist_end;
    tcp::endpoint clientEnd;
    string distHost;
    std::atomic<STAGE> stage;
    tcp::socket proxy_sock;
    void readClientMax(const string &tag, size_t maxSize, const std::function<void(size_t size)> &completeHandler);

    void readClient();

    void writeClient(size_t size);

    void writeClient(const string &tag, size_t size, const std::function<void()> &completeHandler);

    void readProxy();

    void readProxy(size_t size, const std::function<void(boost::system::error_code error)> &completeHandler);

    void writeProxy(size_t size);

    void writeProxy(const string &tag, size_t size, const std::function<void()> &completeHandler);

    void writeProxy(size_t size, const std::function<void(boost::system::error_code error)> &completeHandler);

    void connect_tunnels(const std::function<void(bool)>&complete_handler);

    void directConnect(stream_tunnel *tunnel, const std::function<void(bool)> &completeHandler);

    void proxyConnect(stream_tunnel *tunnel, const std::function<void(bool)> &completeHandler);

    void select_tunnels();

    static void close(tcp::socket &socks, const std::function<void()> &completeHandler);

    void bindLocalPort(basic_endpoint<tcp> &endpoint, boost::system::error_code &error);

    void processError(const boost::system::error_code &error, const string &TAG);


    bool initProxySocks();

    bool nextStage(proxy_session::STAGE nextStage);


#ifdef linux

    void setMark(uint32_t mark);
    uint32_t getMark(int fd);

#endif
};

#endif// ST_PROXY_PROXY_SESSION_H
