//
// Created by codingdie on 9/23/22.
//

#ifndef ST_PROXY_QUALITY_ANALYZER_H
#define ST_PROXY_QUALITY_ANALYZER_H

#include "proto/message.pb.h"
#include "stream_tunnel.h"
#include <boost/asio.hpp>
#define select_tunnels_tesult vector<pair<stream_tunnel *, pair<int, proxy::proto::quality_record>>>
class quality_analyzer {
public:
    static const uint32_t IP_TUNNEL_TEST_COUNT = 3;
    static const uint32_t TUNNEL_TEST_COUNT = 10;

    quality_analyzer();
    virtual ~quality_analyzer();
    static quality_analyzer &uniq();
    void record_failed(uint32_t dist_ip, stream_tunnel *tunnel);

    void record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost);

    st::proxy::proto::quality_record get_record(uint32_t dist_ip);

    st::proxy::proto::quality_record get_record(stream_tunnel *tunnel);

    st::proxy::proto::quality_record get_record(uint32_t dist_ip, stream_tunnel *tunnel);

    unordered_map<string, st::proxy::proto::quality_record> get_all_tunnel_record();

    void delete_record(const string &domain);

    void delete_record(uint32_t ip);

    void set_io_context(io_context *context);

    string analyse_ip(uint32_t ip);

    string analyse_ip_tunnels(uint32_t ip);

    select_tunnels_tesult select_tunnels(uint32_t dist_ip, const vector<string> &dist_hosts, const string &prefer_area);

    uint16_t cal_need_test_count(const select_tunnels_tesult &tunnels);

    string analyse_tunnel();

    void delete_all_record();

private:
    st::kv::disk_kv db;
    io_context *ic = nullptr;
    std::default_random_engine random_engine;
    static string build_key(uint32_t dist_ip, stream_tunnel *tunnel);
    static string build_key(uint32_t dist_ip);
    void add_session_record(const string &key, st::proxy::proto::quality_record &record,
                            const st::proxy::proto::session_record &s_record);
    static void add_session_record(st::proxy::proto::quality_record &record,
                                   const st::proxy::proto::session_record &s_record);
    static void process_record(st::proxy::proto::quality_record &record);
    proxy::proto::quality_record get_record(const string &key);
    void execute(std::function<void()> func);
    void del_ip_all_tunnel_record(uint32_t dist_ip);
    bool check_all_failed(const proxy::proto::quality_record &record);
    static uint8_t need_more_test(const st::proxy::proto::quality_record &record);
    bool has_record_ip_failed(uint32_t dist_ip, const proxy::proto::quality_record &tunnel_record) const;
};


#endif//ST_PROXY_QUALITY_ANALYZER_H
