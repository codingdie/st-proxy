//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
#include "config.h"
#include "leveldb/cache.h"
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
        auto tunnel_record = get_record(dist_ip, tunnel);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), tunnel_record, se, IP_TUNNEL_MAX_QUEUE_SIZE);
        auto ip_record = get_record(dist_ip);
        add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se, IP_MAX_QUEUE_SIZE);
        ip_record = get_record(dist_ip);
        process_record(ip_record, IP_MAX_QUEUE_SIZE, RECORD_EXPIRE_TIME);
        if (need_forbid_ip(ip_record)) {
            proxy::shm::uniq().forbid_ip(dist_ip);
            del_ip_all_tunnel_record(dist_ip);
        }
    });
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
        auto tunnel_record = get_record(dist_ip, tunnel);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), tunnel_record, se, IP_TUNNEL_MAX_QUEUE_SIZE);
        auto ip_record = get_record(dist_ip);
        add_session_record(quality_analyzer::build_key(dist_ip), ip_record, se, IP_MAX_QUEUE_SIZE);
        process_record(ip_record, IP_MAX_QUEUE_SIZE, RECORD_EXPIRE_TIME);
        if (!need_forbid_ip(ip_record)) {
            proxy::shm::uniq().recover_ip(dist_ip);
        }
    });
}


void quality_analyzer::add_session_record(quality_record &record, const session_record &s_record, uint32_t max_size) {
    session_record *new_record;
    if (record.records_size() > max_size) {
        record.clear_records();
        record.clear_queue_size();
    }
    auto queue_size = record.queue_size();
    if (record.records_size() < max_size) {
        new_record = record.add_records();
    } else {
        new_record = record.mutable_records(queue_size % max_size);
    }
    new_record->set_success(s_record.success());
    new_record->set_first_package_cost(s_record.first_package_cost());
    new_record->set_timestamp(time::now());
    record.set_queue_size((queue_size + 1));
}

quality_record quality_analyzer::get_record(uint32_t dist_ip, stream_tunnel *tunnel) {
    auto key = build_key(dist_ip, tunnel);
    quality_record record = get_record(key);
    process_record(record, IP_TUNNEL_MAX_QUEUE_SIZE, RECORD_EXPIRE_TIME);
    return record;
}

quality_record quality_analyzer::get_record(uint32_t dist_ip) {
    auto key = build_key(dist_ip);
    quality_record record = get_record(key);
    record.set_type(st::proxy::proto::IP);
    process_record(record, IP_MAX_QUEUE_SIZE, st::proxy::shm::IP_FORBID_TIME);
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
void quality_analyzer::process_record(quality_record &record, uint32_t max_size, uint32_t expire) {
    auto success = 0;
    auto failed = 0;
    uint64_t cost = 0;
    for (auto i = 0; i < record.records_size() && i < max_size; i++) {
        const session_record &s_record = record.records(i);
        auto time_diff = time::now() - s_record.timestamp();
        if (time_diff > expire) {
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
quality_analyzer::quality_analyzer() : db("st-proxy-quality", 2 * 1024 * 1204) {
    uint32_t ip_count = 0;
    uint32_t ip_tunnel_count = 0;
    db.list([&](const std::string &key, const std::string &value) {
        quality_record record;
        if (!value.empty()) {
            record.ParseFromString(value);
        }
        if (record.type() == IP) {
            ip_count++;
            if (quality_analyzer::need_forbid_ip(record)) {
                proxy::shm::uniq().forbid_ip(ipv4::str_to_ip(key));
            } else {
                proxy::shm::uniq().recover_ip(ipv4::str_to_ip(key));
            }
        } else {
            ip_tunnel_count++;
        }
        return record;
    });
    logger::INFO << "quality analyser has" << ip_count << "ip and " << ip_tunnel_count << "record" << END;
}
string quality_analyzer::build_key(uint32_t dist_ip, stream_tunnel *tunnel) {
    return st::utils::ipv4::ip_to_str(dist_ip) + "/" + tunnel->id();
}
string quality_analyzer::build_key(uint32_t dist_ip) { return st::utils::ipv4::ip_to_str(dist_ip); }

void quality_analyzer::clear() {}
void quality_analyzer::set_io_context(io_context *context) { this->ic = context; }
bool quality_analyzer::is_tunnel_valid(const st::proxy::proto::quality_record &record) {
    return record.first_package_failed() < 3 || record.first_package_success() > 0;
}
bool quality_analyzer::has_enough_data(const quality_record &record) {
    return record.first_package_failed() + record.first_package_success() == IP_TUNNEL_MAX_QUEUE_SIZE;
}
void quality_analyzer::add_session_record(const string &key, quality_record &record,
                                          const st::proxy::proto::session_record &s_record, uint32_t max_size) {
    add_session_record(record, s_record, max_size);
    record.clear_first_package_cost();
    record.clear_first_package_failed();
    record.clear_first_package_success();
    db.put(key, record.SerializeAsString());
}
void quality_analyzer::execute(std::function<void()> func) {
    if (ic != nullptr) {
        ic->post(func);
    } else {
        func();
    }
}
bool quality_analyzer::need_forbid_ip(const quality_record &record) {
    return record.first_package_failed() == IP_MAX_QUEUE_SIZE;
}
unordered_map<string, st::proxy::proto::quality_record> quality_analyzer::get_all_tunnel_record(uint32_t dist_ip) {
    unordered_map<string, st::proxy::proto::quality_record> result;
    for (const auto &tunnel : proxy::config::uniq().tunnels) {
        auto record = get_record(dist_ip, tunnel);
        if (record.records_size() > 0) {
            result.emplace(make_pair(tunnel->id(), record));
        }
    }
    return result;
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
    auto records = get_all_tunnel_record(ip);
    for (auto &record : records) {
        str.append(record.first)
                .append("\t")
                .append(to_string(record.second.first_package_success()))
                .append("\t")
                .append(to_string(record.second.first_package_failed()))
                .append("\t")
                .append(to_string(record.second.first_package_cost()))
                .append("\n");
    }
    strutils::trim(str);
    return str;
}
string quality_analyzer::analyse_domain(const string &domain) {
    string str;
    vector<string> strs;
    for (const auto &ip : st::utils::dns::query(st::proxy::config::uniq().dns, domain)) {
        strs.emplace_back(analyse_ip(ip));
    }
    std::sort(strs.begin(), strs.end(),
              [](const string &str1, const string &str2) { return str2.length() < str1.length(); });
    str = join(strs, "\n\n");
    strutils::trim(str);
    return str;
}
