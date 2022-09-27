//
// Created by codingdie on 9/23/22.
//

#ifndef ST_PROXY_QUALITY_ANALYZER_H
#define ST_PROXY_QUALITY_ANALYZER_H

#include "stream_tunnel.h"
#include <atomic>
#include <boost/asio.hpp>
#include <leveldb/db.h>
#include <unordered_map>
#include <utility>

class quality_record {
public:
    uint32_t first_package_failed = 0;
    uint32_t first_package_success = 0;
    uint64_t first_package_cost_total = 0;
    static quality_record parse(const string &line);
    string to_string() const;
    bool valid() const;
};
class quality_analyzer {
public:
    quality_analyzer();
    static quality_analyzer &uniq();
    void record_first_package_failed(uint32_t dist_ip, stream_tunnel *tunnel);
    void record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost);
    quality_record get_record(uint32_t dist_ip, stream_tunnel *tunnel);
    void clear();
    virtual ~quality_analyzer();
    void set_io_context(io_context *ic);

private:
    io_context *ic = nullptr;
    leveldb::DB *db = nullptr;
    leveldb::Options options;
    mutex lock;
    string build_key(uint32_t dist_ip, stream_tunnel *tunnel);
    void execute_write(const std::function<void()> &op);
};


#endif//ST_PROXY_QUALITY_ANALYZER_H
