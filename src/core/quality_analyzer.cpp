//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
#include "config.h"
#include "leveldb/cache.h"
#include "net_test_manager.h"
#include "utils/shm/proxy_shm.h"
using namespace st::proxy::proto;
quality_analyzer &quality_analyzer::uniq() {
    static quality_analyzer instance;
    return instance;
}

void quality_analyzer::record_failed(uint32_t dist_ip, stream_tunnel *tunnel) {
    execute([=]() {
        session_record se;
        se.set_first_package_cost(0);
        se.set_success(false);
        auto tunnel_record = get_record(tunnel);
        auto ip_record = get_record(dist_ip);
        auto ip_tunnel_record = get_record(dist_ip, tunnel);
        bool ip_tunnel_failed = check_all_failed(ip_tunnel_record);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), ip_tunnel_record, se);
        if (!has_record_ip_failed(dist_ip, tunnel_record)) {
            se.set_ip(dist_ip);
            add_session_record(tunnel->id(), tunnel_record, se);
            se.clear_ip();
        }
        if (!ip_tunnel_failed && check_all_failed(ip_tunnel_record)) {
            add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se);
        }
        if (check_all_failed(ip_record)) {
            proxy::shm::uniq().forbid_ip(dist_ip);
            del_ip_all_tunnel_record(dist_ip);
        }
    });
}
bool quality_analyzer::has_record_ip_failed(uint32_t dist_ip, const quality_record &tunnel_record) const {
    bool contains = false;
    for (const auto &item : tunnel_record.records()) {
        if (!item.success() && item.ip() == dist_ip) {
            contains = true;
            break;
        }
    }
    return contains;
}
void quality_analyzer::del_ip_all_tunnel_record(uint32_t dist_ip) {
    for (const auto &item : proxy::config::uniq().tunnels) {
        db.erase(build_key(dist_ip, item));
    }
}
void quality_analyzer::record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost) {
    execute([=]() {
        session_record se;
        se.set_first_package_cost(cost);
        se.set_success(true);
        auto tunnel_record = get_record(tunnel);
        auto ip_record = get_record(dist_ip);
        auto ip_tunnel_record = get_record(dist_ip, tunnel);
        add_session_record(tunnel->id(), tunnel_record, se);
        add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), ip_tunnel_record, se);
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

st::proxy::proto::quality_record quality_analyzer::get_record(stream_tunnel *tunnel) {
    auto key = tunnel->id();
    quality_record record = get_record(key);
    record.set_queue_limit(TUNNEL_TEST_COUNT);
    record.set_type(st::proxy::proto::TUNNEL);
    process_record(record);
    return record;
}

quality_record quality_analyzer::get_record(uint32_t dist_ip) {
    auto key = build_key(dist_ip);
    quality_record record = get_record(key);
    record.set_queue_limit(st::proxy::config::uniq().tunnels.size());
    record.set_type(st::proxy::proto::IP);
    process_record(record);
    return record;
}
quality_record quality_analyzer::get_record(uint32_t dist_ip, stream_tunnel *tunnel) {
    auto key = build_key(dist_ip, tunnel);
    quality_record record = get_record(key);
    record.set_queue_limit(tunnel->type == "DIRECT" ? IP_TUNNEL_TEST_COUNT * 3 : IP_TUNNEL_TEST_COUNT);
    record.set_type(st::proxy::proto::IP_TUNNEL);
    process_record(record);
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
    for (auto i = 0; i < record.records_size() && i < record.queue_limit(); i++) {
        const session_record &s_record = record.records(i);
        auto time_diff = time::now() - s_record.timestamp();
        if (time_diff > RECORD_EXPIRE_TIME) {
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


quality_analyzer::~quality_analyzer() = default;
quality_analyzer::quality_analyzer() : db("st-proxy-quality", 4 * 1024 * 1204), random_engine(time::now()) {
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
string quality_analyzer::build_key(uint32_t dist_ip, stream_tunnel *tunnel) {
    return st::utils::ipv4::ip_to_str(dist_ip) + "/" + tunnel->id();
}
string quality_analyzer::build_key(uint32_t dist_ip) { return st::utils::ipv4::ip_to_str(dist_ip); }

void quality_analyzer::set_io_context(io_context *context) { this->ic = context; }
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
void quality_analyzer::execute(std::function<void()> func) {
    if (ic != nullptr) {
        ic->post(func);
    } else {
        func();
    }
}
unordered_map<string, st::proxy::proto::quality_record> quality_analyzer::get_all_tunnel_record() {
    unordered_map<string, st::proxy::proto::quality_record> result;
    for (const auto &tunnel : proxy::config::uniq().tunnels) {
        auto record = get_record(tunnel);
        result.emplace(make_pair(tunnel->id(), record));
    }
    return result;
}
string quality_analyzer::analyse_ip_tunnels(uint32_t ip) {
    string str;
    auto tunnels = select_tunnels(ip, {}, "");
    int i = 0;
    for (auto &it : tunnels) {
        stream_tunnel *tunnel = it.first;
        const auto &tunnel_record = it.second.second;
        str.append(to_string(i++))
                .append("\t")
                .append(tunnel->id())
                .append("\t")
                .append(tunnel->area)
                .append("\t")
                .append(to_string(it.second.first))
                .append("\t")
                .append(to_string(tunnel_record.first_package_success()))
                .append("\t")
                .append(to_string(tunnel_record.first_package_failed()))
                .append("\t")
                .append(to_string(tunnel_record.first_package_cost()))
                .append("\n");
    }
    strutils::trim(str);
    return str;
}

string quality_analyzer::analyse_ip(uint32_t ip) {
    string str;
    auto ip_record = get_record(ip);
    str.append(utils::ipv4::ip_to_str(ip))
            .append("\t")
            .append(to_string(ip_record.first_package_success()))
            .append("\t")
            .append(to_string(ip_record.first_package_failed()))
            .append("\t")
            .append(to_string(ip_record.first_package_cost()))
            .append("\n");
    strutils::trim(str);
    return str;
}
select_tunnels_tesult quality_analyzer::select_tunnels(uint32_t dist_ip, const vector<string> &dist_hosts,
                                                       const string &prefer_area) {
    auto begin = time::now();
    select_tunnels_tesult tunnels;
    for (auto it = st::proxy::config::uniq().tunnels.begin(); it != st::proxy::config::uniq().tunnels.end(); it++) {
        stream_tunnel *tunnel = *it.base();
        int score = 1;
        bool inArea = st::areaip::manager::uniq().is_area_ip(tunnel->proxyAreas, dist_ip);
        if (inArea) {
            score += 10;
        }
        const auto &ip_tunnel_record = quality_analyzer::uniq().get_record(dist_ip, tunnel);
        const auto &tunnel_record = quality_analyzer::uniq().get_record(tunnel);
        if (ip_tunnel_record.first_package_success() == 0 && check_all_failed(tunnel_record)) {
            score -= 100;
        }
        if (check_all_failed(ip_tunnel_record)) {
            score -= 1000;
        }
        if (tunnel->in_whitelist(dist_ip) || tunnel->in_whitelist(dist_hosts) || tunnel->area == prefer_area) {
            score += 10000;
        }
        tunnels.emplace_back(tunnel, make_pair(score, ip_tunnel_record));
    }
    sort(tunnels.begin(), tunnels.end(),
         [=](const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &a,
             const pair<stream_tunnel *, pair<int, proxy::proto::quality_record>> &b) {
             if (a.second.first == b.second.first) {
                 const proxy::proto::quality_record &record_a = a.second.second;
                 const proxy::proto::quality_record &record_b = b.second.second;
                 // 基础策略排序优先级差不多情况下
                 // 当收集了足够多的数据后，优先成功率高的，其次优先首包耗时低,否则优先使用没用过的tunnel
                 if (need_more_test(record_a) || need_more_test(record_b)) {
                     return record_a.first_package_success() + record_a.first_package_failed() <
                            record_b.first_package_success() + record_b.first_package_failed();
                 } else {
                     if (record_a.first_package_success() != record_b.first_package_success()) {
                         return record_a.first_package_success() > record_b.first_package_success();
                     } else {
                         if (record_a.first_package_cost() != record_b.first_package_cost()) {
                             return record_a.first_package_cost() < record_b.first_package_cost();
                         }
                     }
                 }
             }
             return a.second.first > b.second.first;
         });
    apm_logger::perf("st-proxy-select-tunnels", {}, time::now() - begin);
    return tunnels;
}
uint16_t quality_analyzer::cal_need_test_count(const select_tunnels_tesult &tunnels) {
    int need_test_count = 0;
    int max_score = tunnels[0].second.first;
    for (const auto &item : tunnels) {
        if (item.second.first == max_score) {
            need_test_count += this->need_more_test(item.second.second);
        }
    }
    return need_test_count;
}
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
            db.erase(build_key(ip, item));
        }
    });
}
string quality_analyzer::analyse_tunnel() {
    string str;
    unordered_map<string, st::proxy::proto::quality_record> result;
    for (const auto &tunnel : proxy::config::uniq().tunnels) {
        auto record = get_record(tunnel);
        vector<string> failed_ips;
        for (const auto &item : record.records()) {
            if (!item.success()) {
                failed_ips.emplace_back(ipv4::ip_to_str(item.ip()));
            }
        }
        str.append(tunnel->id())
                .append("\t")
                .append(tunnel->area)
                .append("\t")
                .append(to_string(record.first_package_success()))
                .append("\t")
                .append(to_string(record.first_package_failed()))
                .append("\t")
                .append(to_string(record.first_package_cost()))
                .append("\t")
                .append(join(failed_ips, ","))
                .append("\n");
    }
    strutils::trim(str);
    return str;
}
void quality_analyzer::delete_all_record() {
    for (const auto &item : proxy::config::uniq().tunnels) {
        db.erase(item->id());
    }
}
bool quality_analyzer::check_all_failed(const select_tunnels_tesult &result) {
    for (const auto &item : result) {
        if (check_all_failed(item.second.second)) {
            return true;
        }
    }
    return false;
}
