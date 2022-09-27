//
// Created by codingdie on 9/23/22.
//

#include "quality_analyzer.h"
#include "leveldb/cache.h"
quality_analyzer &quality_analyzer::uniq() {
    static quality_analyzer instance;
    return instance;
}

void quality_analyzer::record_first_package_failed(uint32_t dist_ip, stream_tunnel *tunnel) {
    execute_write([=]() {
        string data;
        auto key = this->build_key(dist_ip, tunnel);
        leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
        quality_record record;
        if (s.ok()) {
            record = quality_record::parse(data);
        }
        record.first_package_failed++;
        db->Put(leveldb::WriteOptions(), key, record.to_string());
    });
}
void quality_analyzer::record_first_package_success(uint32_t dist_ip, stream_tunnel *tunnel, uint64_t cost) {
    execute_write([=]() {
        string data;
        auto key = build_key(dist_ip, tunnel);
        leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
        quality_record record;
        if (s.ok()) {
            record = quality_record::parse(data);
        }
        record.first_package_success++;
        record.first_package_cost_total += cost;
        db->Put(leveldb::WriteOptions(), key, record.to_string());
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
    string data;
    auto key = build_key(dist_ip, tunnel);
    leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &data);
    if (s.ok()) {
        return quality_record::parse(data);
    }
    return {};
}


quality_analyzer::~quality_analyzer() {
    if (db != nullptr) {
        delete db;
    }
    if (options.block_cache != nullptr) {
        delete options.block_cache;
    }
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
quality_record quality_record::parse(const string &line) {
    auto split = st::utils::strutils::split(line, "\t");
    quality_record record;
    record.first_package_success = stoul(split[0]);
    record.first_package_failed = stoul(split[1]);
    record.first_package_cost_total = stoul(split[2]);
    return record;
}
string quality_record::to_string() const {
    return ::to_string(first_package_success) + "\t" + ::to_string(first_package_failed) + "\t" +
           ::to_string(first_package_cost_total);
}
bool quality_record::valid() const { return first_package_failed < 5 || first_package_success > 0; }
