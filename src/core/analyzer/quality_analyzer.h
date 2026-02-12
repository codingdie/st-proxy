//
// Created by codingdie on 9/23/22.
//

#ifndef ST_PROXY_QUALITY_ANALYZER_H
#define ST_PROXY_QUALITY_ANALYZER_H

#include "message.pb.h"
#include "st.h"
#include "stream_tunnel.h"
#include <boost/asio.hpp>
#define select_tunnels_tesult vector<pair<stream_tunnel *, pair<int, proxy::proto::quality_record>>>

class quality_analyzer {
public:
    static const uint32_t IP_TUNNEL_TEST_COUNT = 3;
    static const uint32_t TUNNEL_TEST_COUNT = 20;
    static const uint32_t IP_BLACKLIST_EXPIRE_MINUTES = 60; // 黑名单过期时间：1小时

    quality_analyzer();

    virtual ~quality_analyzer();

    static quality_analyzer &uniq();

    select_tunnels_tesult select_tunnels(uint32_t dist_ip, uint16_t port, const vector<string> &dist_hosts,
                                         const string &prefer_area);

    void record_failed(uint32_t dist_ip, const string &tunnel_id);

    void record_first_package_success(uint32_t dist_ip, const string &tunnel, uint64_t cost);

    st::proxy::proto::quality_record get_ip_record(uint32_t dist_ip);

    st::proxy::proto::quality_record get_tunnel_record(const string &tunnel);

    st::proxy::proto::quality_record get_ip_tunnel_record(uint32_t dist_ip, const string &tunnel_id);

    void delete_record(const string &domain);

    void delete_record(uint32_t ip);

    void delete_all_record();

    static bool check_all_failed(const proxy::proto::quality_record &record);

    void clear();

    // 黑名单相关方法
    void add_to_blacklist(uint32_t ip);
    bool is_in_blacklist(uint32_t ip);
    void remove_from_blacklist(uint32_t ip);
    std::vector<uint32_t> get_blacklist_ips();

    static int64_t get_min_expire_minutes(const st::proxy::proto::quality_record &record);

private:
    st::kv::disk_kv db;
    st::kv::disk_kv blacklist_db; // 黑名单专用数据库
    io_context ic;
    io_context::work *worker;
    std::thread *th;
    std::default_random_engine random_engine;

    static string build_key(uint32_t dist_ip, const string &tunnel);
    static string build_key(uint32_t dist_ip);
    void add_session_record(const string &key, st::proxy::proto::quality_record &record,
                            const st::proxy::proto::session_record &s_record);
    static void add_session_record(st::proxy::proto::quality_record &record,
                                   const st::proxy::proto::session_record &s_record);
    static void process_record(st::proxy::proto::quality_record &record);
    proxy::proto::quality_record get_record(const string &key);
    void execute(std::function<void()> func);
    static uint8_t need_more_test(const st::proxy::proto::quality_record &record);

    static bool has_record_ip_failed(uint32_t dist_ip, const proxy::proto::quality_record &tunnel_record);


    void try_analyze(uint32_t dist_ip, uint16_t port, const select_tunnels_tesult &stt);
};


#endif//ST_PROXY_QUALITY_ANALYZER_H
