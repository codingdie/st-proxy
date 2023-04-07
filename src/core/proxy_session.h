//
// Created by codingdie on 2020/9/17.
//

#ifndef ST_PROXY_PROXY_SESSION_H
#define ST_PROXY_PROXY_SESSION_H

#include "common.h"

class proxy_session {
public:
    enum STAGE { CONNECTING, CONNECTED, DESTROYING, DESTROYED };
    static const uint32_t PROXY_BUFFER_SIZE = 1024;
    uint64_t id;
    uint16_t port = 0;
    st::utils::counters::interval read_counter;
    st::utils::counters::interval write_counter;
    stream_tunnel *connected_tunnel = nullptr;
    tcp::socket client_sock;
    string tag;
    explicit proxy_session(io_context &context, string tag);

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
    vector<stream_tunnel *> selected_tunnels;
    byte *out_buffer;
    byte *in_buffer;
    mutex stageLock;
    uint64_t try_connect_index = 0;
    uint64_t begin = 0;
    string prefer_area;
    string dist_area;
    tcp::endpoint dist_end;
    tcp::endpoint client_end;
    vector<string> dist_hosts;
    std::atomic<STAGE> stage;
    tcp::socket proxy_sock;
    bool is_net_test() const;

    void read_client_max(const string &tag, size_t maxSize, const std::function<void(size_t size)> &completeHandler);

    void read_client();

    void write_client(size_t writeSize);

    void write_client(const string &tag, size_t writeSize, const std::function<void()> &completeHandler);

    void read_proxy();

    void read_proxy(size_t size, const std::function<void(boost::system::error_code error)> &complete);

    void write_proxy(size_t writeSize);

    void write_proxy(const string &tag, size_t writeSize, const std::function<void()> &completeHandler);

    void write_proxy(size_t writeSize, const std::function<void(boost::system::error_code error)> &completeHandler);

    void connect_tunnels(const std::function<void(bool)> &complete_handler);

    void direct_connect(const std::function<void(bool)> &completeHandler);

    void proxy_connect(stream_tunnel *tunnel, const std::function<void(bool)> &complete);

    void select_tunnels();

    static void close(tcp::socket &socks, const std::function<void()> &completeHandler);

    void bind_local_port(basic_endpoint<tcp> &endpoint, boost::system::error_code &error);

    void process_error(const boost::system::error_code &error, const string &TAG);

    bool init_proxy_socks();

    bool nextStage(proxy_session::STAGE nextStage);
};

#endif// ST_PROXY_PROXY_SESSION_H
