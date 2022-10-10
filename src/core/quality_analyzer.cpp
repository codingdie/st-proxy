//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
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
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), IP_TUNNEL, se, IP_TUNNEL_MAX_QUEUE_SIZE);
        add_session_record(quality_analyzer::build_key(dist_ip), IP, se, IP_MAX_QUEUE_SIZE);
        if (check_ip_forbid(dist_ip)) {
            proxy::shm::uniq().forbid_ip(dist_ip);
        }
    });
}
void quality_analyzer::record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost) {
    execute([=]() {
        session_record se;
        se.set_first_package_cost(cost);
        se.set_success(true);
        add_session_record(quality_analyzer::build_key(dist_ip, tunnel), IP_TUNNEL, se, IP_TUNNEL_MAX_QUEUE_SIZE);
        add_session_record(quality_analyzer::build_key(dist_ip), IP, se, IP_MAX_QUEUE_SIZE);
        if (!check_ip_forbid(dist_ip)) {
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
    uint32_t queue_size = record.queue_size();
    if (record.records_size() < max_size) {
        new_record = record.add_records();
    } else {
        auto back_pos = queue_size % max_size;
        new_record = record.mutable_records(back_pos);
    }
    new_record->set_success(s_record.success());
    new_record->set_first_package_cost(s_record.first_package_cost());
    new_record->set_timestamp(time::now());
    record.set_queue_size((queue_size + 1));
}

quality_record quality_analyzer::get_record(uint32_t dist_ip, stream_tunnel *tunnel) {
    auto key = build_key(dist_ip, tunnel);
    quality_record record = get_record(key);

    process_record(record, IP_TUNNEL_MAX_QUEUE_SIZE, 1000L * 60 * 60 * 24);
    return record;
}

quality_record quality_analyzer::get_record(uint32_t dist_ip) {
    auto key = build_key(dist_ip);
    quality_record record = get_record(key);
    process_record(record, IP_MAX_QUEUE_SIZE, st::proxy::shm::IP_FORBID_TIME);
    return record;
}
quality_record quality_analyzer::get_record(const string &key) {
    quality_record record;
    string data;
    leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
    if (s.ok()) {
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


quality_analyzer::~quality_analyzer() {
    delete db;
    delete options.block_cache;
}
quality_analyzer::quality_analyzer() {
    options.create_if_missing = true;
    st::utils::file::mkdirs("/var/lib/st/proxy");
    leveldb::Status status = leveldb::DB::Open(options, "/var/lib/st/proxy/quality", &db);
    options.block_cache = leveldb::NewLRUCache(1024 * 1024 * 1);
    assert(status.ok());
}
string quality_analyzer::build_key(uint32_t dist_ip, stream_tunnel *tunnel) {
    return st::utils::ipv4::ip_to_str(dist_ip) + "/" + tunnel->id();
}
string quality_analyzer::build_key(uint32_t dist_ip) { return st::utils::ipv4::ip_to_str(dist_ip); }

void quality_analyzer::clear() {}
void quality_analyzer::set_io_context(io_context *ic) { this->ic = ic; }
bool quality_analyzer::is_valid(const st::proxy::proto::quality_record &record) {
    return record.first_package_failed() < 3 || record.first_package_success() > 0;
}
bool quality_analyzer::is_enough(const quality_record &record) {
    return record.first_package_failed() + record.first_package_success() == IP_TUNNEL_MAX_QUEUE_SIZE;
}
void quality_analyzer::add_session_record(const string &key, st::proxy::proto::record_type record_type,
                                          const st::proxy::proto::session_record &s_record, uint32_t max_size) {
    std::string data;
    leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
    quality_record record;
    if (s.ok()) {
        record.ParseFromString(data);
    }
    add_session_record(record, s_record, max_size);
    record.set_type(record_type);
    db->Put(leveldb::WriteOptions(), key, record.SerializeAsString());
}
void quality_analyzer::execute(std::function<void()> func) {
    if (ic != nullptr) {
        ic->post(func);
    } else {
        func();
    }
}
bool quality_analyzer::check_ip_forbid(uint32_t dist_ip) {
    quality_record record = get_record(dist_ip);
    return record.first_package_failed() == IP_MAX_QUEUE_SIZE;
}
