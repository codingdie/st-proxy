//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
#include "command/dns_command.h"
#include "config.h"
#include "leveldb/cache.h"
#include "net_test_manager.h"
#include "utils/shm/proxy_shm.h"
using namespace st::proxy::proto;
quality_analyzer &quality_analyzer::uniq() {
    static quality_analyzer instance;
    return instance;
}

void quality_analyzer::record_failed(uint32_t dist_ip, const string &tunnel_id) {
    execute([=]() {
        session_record se;
        se.set_first_package_cost(0);
        se.set_success(false);
        auto tunnel_record = get_tunnel_record(tunnel_id);
        auto ip_record = get_ip_record(dist_ip);
        auto ip_tunnel_record = get_ip_tunnel_record(dist_ip, tunnel_id);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel_id), ip_tunnel_record, se);
        bool ip_tunnel_all_failed = check_all_failed(ip_tunnel_record);
        if (!has_record_ip_failed(dist_ip, tunnel_record) && ip_tunnel_all_failed) {
            se.set_ip(dist_ip);
            add_session_record(tunnel_id, tunnel_record, se);
            se.clear_ip();
        }
        if (!ip_tunnel_all_failed) {
            add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se);
        }
        if (check_all_failed(ip_record)) {
            proxy::shm::uniq().forbid_ip(dist_ip);
            delete_record(dist_ip);
        }
    });
}
bool quality_analyzer::has_record_ip_failed(uint32_t dist_ip, const quality_record &tunnel_record) {
    bool contains = false;
    for (const auto &item : tunnel_record.records()) {
        if (!item.success() && item.ip() == dist_ip) {
            contains = true;
            break;
        }
    }
    return contains;
}

void quality_analyzer::record_first_package_success(uint32_t dist_ip, const string &tunnel_id, uint64_t cost) {
    execute([=]() {
        session_record se;
        se.set_first_package_cost(cost);
        se.set_success(true);
        auto tunnel_record = get_tunnel_record(tunnel_id);
        auto ip_record = get_ip_record(dist_ip);
        auto ip_tunnel_record = get_ip_tunnel_record(dist_ip, tunnel_id);
        add_session_record(tunnel_id, tunnel_record, se);
        add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel_id), ip_tunnel_record, se);
        if (!check_all_failed(ip_record)) {
            proxy::shm::uniq().recover_ip(dist_ip);
        }
    });
}


void quality_analyzer::add_session_record(quality_record &record, const session_record &s_record) {
    session_record *new_record;
    if (record.records_size() > record.queue_limit()) {
        record.clear_records();
        record.clear_queue_size();
    }
    auto queue_size = record.queue_size();
    if (record.records_size() < record.queue_limit()) {
        new_record = record.add_records();
    } else {
        new_record = record.mutable_records(queue_size % record.queue_limit());
    }
    new_record->set_success(s_record.success());
    new_record->set_ip(s_record.ip());
    new_record->set_first_package_cost(s_record.first_package_cost());
    new_record->set_timestamp(time::now());
    record.set_queue_size((queue_size + 1));
}

st::proxy::proto::quality_record quality_analyzer::get_tunnel_record(const string &tunnel_id) {
    auto begin = time::now();
    quality_record record = get_record(tunnel_id);
    record.set_queue_limit(TUNNEL_TEST_COUNT);
    record.set_type(st::proxy::proto::TUNNEL);
    process_record(record);
    apm_logger::perf("st-proxy-get-tunnel-record", {}, time::now() - begin);
    return record;
}

quality_record quality_analyzer::get_ip_record(uint32_t dist_ip) {
    auto key = build_key(dist_ip);
    quality_record record = get_record(key);
    record.set_queue_limit(std::max((uint32_t) st::proxy::config::uniq().tunnels.size(), (uint32_t) 3U));
    record.set_type(st::proxy::proto::IP);
    process_record(record);
    return record;
}
quality_record quality_analyzer::get_ip_tunnel_record(uint32_t dist_ip, const string &tunnel_id) {
    auto begin = time::now();
    auto key = build_key(dist_ip, tunnel_id);
    quality_record record = get_record(key);
    record.set_queue_limit(IP_TUNNEL_TEST_COUNT);
    record.set_type(st::proxy::proto::IP_TUNNEL);
    process_record(record);
    apm_logger::perf("st-proxy-get-ip-tunnel-record", {}, time::now() - begin);
    return record;
}

quality_record quality_analyzer::get_record(const string &key) {
    quality_record record;
    string data = db.get(key);
    if (!data.empty()) {
        record.ParseFromString(data);
    }
    return record;
}
void quality_analyzer::process_record(quality_record &record) {
    auto success = 0;
    auto failed = 0;
    uint64_t cost = 0;
    uint32_t record_expire_time = 1000L * 60 * 60;
    if (record.type() != st::proxy::proto::IP_TUNNEL) {
        record_expire_time = 1000L * 60 * 60 * 12;
    }
    for (auto i = 0; i < record.records_size() && i < record.queue_limit(); i++) {
        const session_record &s_record = record.records(i);
        auto time_diff = time::now() - s_record.timestamp();
        if (time_diff > record_expire_time) {
            continue;
        }
        if (s_record.success()) {
            success++;
            cost += s_record.first_package_cost();
        } else {
            failed++;
        }
    }
    if (success > 0) {
        cost /= success;
        record.set_first_package_cost(cost);
    }
    record.set_first_package_success(success);
    record.set_first_package_failed(failed);
}


quality_analyzer::~quality_analyzer() {
    ic.stop();
    delete worker;
    th->join();
    delete th;
};
quality_analyzer::quality_analyzer()
    : db("st-proxy-quality", 4 * 1024 * 1204), ic(), worker(new boost::asio::io_context::work(ic)),
      th(new thread([this]() { ic.run(); })) {
    uint32_t ip_count = 0;
    uint32_t record_count = 0;
    db.list([&](const std::string &key, const std::string &value) {
        quality_record record;
        if (!value.empty()) {
            record.ParseFromString(value);
            process_record(record);
        }
        record_count++;
        if (record.type() == IP) {
            ip_count++;
            if (quality_analyzer::check_all_failed(record)) {
                proxy::shm::uniq().forbid_ip(ipv4::str_to_ip(key));
            } else {
                proxy::shm::uniq().recover_ip(ipv4::str_to_ip(key));
            }
        }
        return record;
    });
    logger::INFO << "quality analyser has" << ip_count << "ip and " << record_count << "record" << END;
}
string quality_analyzer::build_key(uint32_t dist_ip, const string &tunnel_id) {
    return st::utils::ipv4::ip_to_str(dist_ip) + "/" + tunnel_id;
}
string quality_analyzer::build_key(uint32_t dist_ip) { return st::utils::ipv4::ip_to_str(dist_ip); }

uint8_t quality_analyzer::need_more_test(const quality_record &record) {
    uint32_t result = record.queue_limit() - (record.first_package_failed() + record.first_package_success());
    return std::min(record.queue_limit(), result);
}

void quality_analyzer::add_session_record(const string &key, quality_record &record,
                                          const st::proxy::proto::session_record &s_record) {
    add_session_record(record, s_record);
    record.clear_first_package_cost();
    record.clear_first_package_failed();
    record.clear_first_package_success();
    db.put(key, record.SerializeAsString());
    process_record(record);
}
void quality_analyzer::execute(std::function<void()> func) { ic.post(func); }

bool quality_analyzer::check_all_failed(const quality_record &record) {
    return need_more_test(record) == 0 && record.first_package_success() == 0;
}
void quality_analyzer::delete_record(const string &domain) {
    for (const auto &ip : st::utils::dns::query(st::proxy::config::uniq().dns, domain)) {
        delete_record(ip);
    }
}
void quality_analyzer::delete_record(uint32_t ip) {
    execute([=]() {
        for (const auto &item : st::proxy::config::uniq().tunnels) {
            db.erase(build_key(ip, item->id()));
        }
        db.erase(build_key(ip));
    });
}
void quality_analyzer::delete_all_record() {
    for (const auto &item : proxy::config::uniq().tunnels) {
        db.erase(item->id());
    }
}
void quality_analyzer::clear() { db.clear(); }


select_tunnels_tesult quality_analyzer::select_tunnels(uint32_t dist_ip, uint16_t port,
                                                       const vector<string> &dist_hosts, const string &prefer_area) {
    auto begin = time::now();
    select_tunnels_tesult result;
    for (auto it = st::proxy::config::uniq().tunnels.begin(); it != st::proxy::config::uniq().tunnels.end(); it++) {
        stream_tunnel *tunnel = *it.base();
        int score = 1;
        bool inArea = st::areaip::manager::uniq().is_area_ip(tunnel->proxyAreas, dist_ip);
        if (inArea) {
            score += 10;
        }
        const auto &ip_tunnel_record = quality_analyzer::uniq().get_ip_tunnel_record(dist_ip, tunnel->id());
        const auto &tunnel_record = quality_analyzer::uniq().get_tunnel_record(tunnel->id());
        if (ip_tunnel_record.first_package_success() == 0 && quality_analyzer::check_all_failed(tunnel_record)) {
            score -= 100;
        }
        if (quality_analyzer::check_all_failed(ip_tunnel_record)) {
            score -= 1000;
        }
        if (tunnel->in_whitelist(dist_ip) || tunnel->in_whitelist(dist_hosts) || tunnel->area == prefer_area) {
            score += 10000;
        }
        result.emplace_back(tunnel, make_pair(score, ip_tunnel_record));
    }
    apm_logger::perf("st-proxy-select-tunnels-cal-score", {}, time::now() - begin);
    sort(result.begin(), result.end(),
         [=](const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &a,
             const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &b) {
             if (a.second.first == b.second.first) {
                 const proxy::proto::quality_record &record_a = a.second.second;
                 const proxy::proto::quality_record &record_b = b.second.second;
                 auto su_a = min(1U, record_a.first_package_success());
                 auto su_b = min(1U, record_b.first_package_success());
                 if (su_a != su_b) {
                     return su_a > su_b;
                 } else {
                     auto f_a = record_a.first_package_failed();
                     auto f_b = record_a.first_package_failed();
                     if (f_a != f_b) {
                         return f_b > f_a;
                     } else {
                         if (record_a.first_package_cost() != record_b.first_package_cost()) {
                             return record_a.first_package_cost() < record_b.first_package_cost();
                         }
                     }
                 }
                 // 基础策略排序优先级差不多情况下
                 // 当收集了足够多的数据后，优先成功率高的，其次优先首包耗时低,否则优先使用没用过的tunnel
                 //                 if (need_more_test(record_a) || need_more_test(record_b)) {
                 //                     return record_a.first_package_success() + record_a.first_package_failed() <
                 //                            record_b.first_package_success() + record_b.first_package_failed();
                 //                 }
             }
             return a.second.first > b.second.first;
         });
    apm_logger::perf("st-proxy-select-tunnels", {}, time::now() - begin);
    try_analyze(dist_ip, port, result);
    return result;
}


void quality_analyzer::try_analyze(uint32_t dist_ip, uint16_t port, const select_tunnels_tesult &stt) {
    if (port == 443 && !stt.empty()) {
        int max_score = stt[0].second.first;
        for (const auto &item : stt) {
            auto &record = item.second.second;
            if (item.second.first == max_score) {
                vector<uint16_t> result;
                stream_tunnel *tunnel = item.first;
                for (auto i = record.first_package_failed() + record.first_package_success(); i < 1; i++) {
                    test_case tc;
                    tc.ip = dist_ip;
                    tc.port = port;
                    tc.tunnel_id = tunnel->id();
                    tc.tunnel_test_index = i;
                    if (tunnel->type == "SOCKS") {
                        tc.proxy.ip = tunnel->ip;
                        tc.proxy.port = tunnel->port;
                    }
                    st::task::priority_task<test_case> task(
                            tc, tunnel->type == "DIRECT" ? 0 : 100 + (record.queue_limit() - i), tc.key());
                    net_test_manager::uniq().submit(task);
                }
            } else {
                break;
            }
        }
    }
}