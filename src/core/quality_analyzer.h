//
// Created by codingdie on 9/23/22.
//

#ifndef ST_PROXY_QUALITY_ANALYZER_H
#define ST_PROXY_QUALITY_ANALYZER_H

#include "message.pb.h"
#include "stream_tunnel.h"
#include <atomic>
#include <boost/asio.hpp>
#include <leveldb/db.h>
#include <queue>
#include <unordered_map>
#include <utility>
class quality_analyzer {
public:
    quality_analyzer();
    static quality_analyzer &uniq();
    void record_first_package_failed(uint32_t dist_ip, stream_tunnel *tunnel);
    void record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost);
    st::proxy::proto::quality_record get_record(uint32_t dist_ip, stream_tunnel *tunnel);
    static bool is_valid(const st::proxy::proto::quality_record &record);
    static bool is_enough(const st::proxy::proto::quality_record &record);

    void clear();
    virtual ~quality_analyzer();
    void set_io_context(io_context *ic);
    const static uint8_t MAX_QUEUE_SIZE = 5;

private:
    io_context *ic = nullptr;
    leveldb::DB *db = nullptr;
    leveldb::Options options;
    mutex lock;
    static string build_key(uint32_t dist_ip, stream_tunnel *tunnel);
    void execute_write(const std::function<void()> &op);
    static void add_session_record(proxy::proto::quality_record &record, proxy::proto::session_record &s_record);
};


#endif//ST_PROXY_QUALITY_ANALYZER_H
