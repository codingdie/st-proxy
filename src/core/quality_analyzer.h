//
// Created by codingdie on 9/23/22.
//

#ifndef ST_PROXY_QUALITY_ANALYZER_H
#define ST_PROXY_QUALITY_ANALYZER_H

#include "proto/message.pb.h"
#include "stream_tunnel.h"
#include <boost/asio.hpp>
class quality_analyzer {
public:
    quality_analyzer();
    static quality_analyzer &uniq();
    void record_failed(uint32_t dist_ip, stream_tunnel *tunnel);
    void record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost);
    st::proxy::proto::quality_record get_record(uint32_t dist_ip, stream_tunnel *tunnel);
    st::proxy::proto::quality_record get_record(uint32_t dist_ip);
    static bool is_valid(const st::proxy::proto::quality_record &record);
    static bool is_enough(const st::proxy::proto::quality_record &record);

    void clear();
    virtual ~quality_analyzer();
    void set_io_context(io_context *context);
    static const uint8_t IP_TUNNEL_MAX_QUEUE_SIZE = 3;
    static const uint8_t IP_MAX_QUEUE_SIZE = 10;

private:
    st::kv::disk_kv db;
    io_context *ic = nullptr;
    static string build_key(uint32_t dist_ip, stream_tunnel *tunnel);
    static string build_key(uint32_t dist_ip);
    void add_session_record(const string &key, st::proxy::proto::quality_record &record,
                            const st::proxy::proto::session_record &s_record, uint32_t max_size);
    static void add_session_record(st::proxy::proto::quality_record &record,
                                   const st::proxy::proto::session_record &s_record, uint32_t max_size);
    static void process_record(st::proxy::proto::quality_record &record, uint32_t max_size, uint32_t expire);
    proxy::proto::quality_record get_record(const string &key);
    void execute(std::function<void()> func);
    bool need_forbid_ip(const proxy::proto::quality_record &record);
    void del_ip_all_tunnel_record(uint32_t dist_ip);
};


#endif//ST_PROXY_QUALITY_ANALYZER_H
