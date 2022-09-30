//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
#include "leveldb/cache.h"
using namespace st::proxy::proto;
quality_analyzer &quality_analyzer::uniq() {
    static quality_analyzer instance;
    return instance;
}

void quality_analyzer::record_first_package_failed(uint32_t dist_ip, stream_tunnel *tunnel) {
    execute_write([=]() {
        string data;
        auto key = quality_analyzer::build_key(dist_ip, tunnel);
        leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
        quality_record record;
        if (s.ok()) {
            record.ParseFromString(data);
        }
        session_record se;
        se.set_first_package_cost(0);
        se.set_success(false);
        add_session_record(record, se);
        db->Put(leveldb::WriteOptions(), key, record.SerializeAsString());
    });
}
void quality_analyzer::add_session_record(quality_record &record, session_record &s_record) {
    session_record *new_record;
    if (record.records_size() > MAX_QUEUE_SIZE) {
        record.clear_records();
        record.clear_queue_size();
    }
    uint32_t queue_size = record.queue_size();
    if (record.records_size() < MAX_QUEUE_SIZE) {
        new_record = record.add_records();
    } else {
        auto back_pos = queue_size % MAX_QUEUE_SIZE;
        new_record = record.mutable_records(back_pos);
    }
    new_record->set_success(s_record.success());
    new_record->set_first_package_cost(s_record.first_package_cost());
    new_record->set_timestamp(time::now());
    record.set_queue_size((queue_size + 1));
}
void quality_analyzer::record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost) {
    execute_write([=]() {
        string data;
        auto key = build_key(dist_ip, tunnel);
        leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
        quality_record record;
        if (s.ok()) {
            record.ParseFromString(data);
        }
        session_record se;
        se.set_first_package_cost(cost);
        se.set_success(true);
        add_session_record(record, se);
        db->Put(leveldb::WriteOptions(), key, record.SerializeAsString());
    });
}
void quality_analyzer::execute_write(const std::function<void()> &op) {
    if (ic != nullptr) {
        ic->post(op);
    } else {
        op();
    }
}

quality_record quality_analyzer::get_record(uint32_t dist_ip, stream_tunnel *tunnel) {
    quality_record record;
    string data;
    auto key = build_key(dist_ip, tunnel);
    leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
    if (s.ok()) {
        record.ParseFromString(data);
    }
    auto success = 0;
    auto failed = 0;
    uint64_t cost = 0;
    for (auto i = 0; i < record.records_size() && i < MAX_QUEUE_SIZE; i++) {
        const session_record &s_record = record.records(i);
        auto time_diff = time::now() - s_record.timestamp();
        if (time_diff > 1000L * 60 * 60 * 24) {
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
    return record;
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
void quality_analyzer::clear() {}
void quality_analyzer::set_io_context(io_context *ic) { this->ic = ic; }
bool quality_analyzer::is_valid(const st::proxy::proto::quality_record &record) {
    return record.first_package_failed() < 3 || record.first_package_success() > 0;
}
bool quality_analyzer::is_enough(const quality_record &record) {
    return record.first_package_failed() + record.first_package_success() == MAX_QUEUE_SIZE;
}
