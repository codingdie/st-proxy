//
// Created by codingdie on 2020/6/30.
//

#include "Config.h"

using namespace st::proxy;
Config Config::INSTANCE;

void Config::load(const string &configPathInput) {
    baseConfDir = boost::filesystem::absolute(configPathInput).normalize().string();
    string configPath = configPathInput + "/config.json";
    if (st::utils::file::exit(configPath)) {
        ptree tree;
        try {
            read_json(configPath, tree);
        } catch (json_parser_error e) {
            Logger::ERROR << " parse config file " + configPath + " error!" << e.message() << END;
            exit(1);
        }
        this->ip = tree.get("ip", string(this->ip));
        this->port = stoi(tree.get("port", to_string(this->port)));
        this->soTimeout = stoi(tree.get("so_timeout", to_string(this->soTimeout)));
        this->connectTimeout = stoi(tree.get("connect_timeout", to_string(this->connectTimeout)));
        this->parallel = stoi(tree.get("parallel", to_string(this->parallel)));
        this->dns = tree.get("dns", string(this->dns));
        auto whitelistNode = tree.get_child_optional("whitelist");
        if (whitelistNode.is_initialized()) {
            auto whitelistArr = whitelistNode.get();
            for (boost::property_tree::ptree::value_type &v : whitelistArr) {
                auto domain = v.second.get_value<string>();
                this->whitelist.emplace(domain);
            }
            this->whitelistIPs = parseWhitelistToIPs(this->whitelist);
        }
        auto tunnelNodes = tree.get_child("tunnels");
        if (!tunnelNodes.empty()) {
            for (auto it = tunnelNodes.begin(); it != tunnelNodes.end(); it++) {
                StreamTunnel *streamTunnel = parseStreamTunnel(it->second);
                tunnels.emplace_back(streamTunnel);
            }
        }
        Logger::init(tree);

    } else {
        Logger::INFO << "st-proxy config file not exit!" << configPath << END;
        exit(1);
    }
}
set<uint32_t> Config::parseWhitelistToIPs(const set<string> &whitelist) const {
    set<uint32_t> whitelistIPs;
    for (auto domain : whitelist) {
        if (st::utils::ipv4::strToIp(domain) > 0) {
            whitelistIPs.emplace(st::utils::ipv4::strToIp(domain));
        } else {
            if (domain[0] == '*') {
                continue;
            }
            auto ips = resovleDomain(domain);
            if (ips.size() == 0) {
                Logger::ERROR << "resovle whitelist to ip failed!" << domain << domain << END;
                exit(1);
            }
            for (auto ip : ips) {
                whitelistIPs.emplace(ip);
            }
        }
    }
    return whitelistIPs;
};

template<class K, class D, class C>
StreamTunnel *Config::parseStreamTunnel(basic_ptree<K, D, C> &tunnel) const {
    string type = tunnel.get("type", "DIRECT");
    if (type.empty()) {
        Logger::ERROR << "tunnel type empty!" << END;
        exit(1);
    }
    string serverIp = tunnel.get("ip", "");
    int serverPort = tunnel.get("port", 0);
    if (type != "DIRECT") {
        if (serverIp.empty()) {
            Logger::ERROR << "tunnel ip empty!" << END;
            exit(1);
        }
        if (serverPort <= 0) {
            Logger::ERROR << "tunnel port empty!" << END;
            exit(1);
        }
    }

    StreamTunnel *streamTunnel = new StreamTunnel(type, serverIp, serverPort);
    streamTunnel->area = tunnel.get("area", "");
    boost::optional<basic_ptree<K, D, C> &> areaListNode = tunnel.get_child_optional("areas");
    if (areaListNode.is_initialized()) {
        basic_ptree<K, D, C> arealistArr = areaListNode.get();
        for (boost::property_tree::ptree::value_type &v : arealistArr) {
            string area = v.second.get_value<string>();
            if (!st::areaip::loadAreaIPs(area)) {
                exit(1);
            }
            streamTunnel->proxyAreas.emplace_back(area);
        }
    }
    if (streamTunnel->area.length() > 0) {
        streamTunnel->proxyAreas.insert(streamTunnel->proxyAreas.begin(), streamTunnel->area);
    }
    boost::optional<basic_ptree<K, D, C> &> whitelistNode = tunnel.get_child_optional("whitelist");
    if (whitelistNode.is_initialized()) {
        basic_ptree<K, D, C> whitelistArr = whitelistNode.get();
        for (boost::property_tree::ptree::value_type &v : whitelistArr) {
            string domain = v.second.get_value<string>();
            streamTunnel->whitelist.emplace(domain);
        }
        streamTunnel->whitelistIPs = parseWhitelistToIPs(streamTunnel->whitelist);
    }
    return streamTunnel;
}
vector<uint32_t> Config::resovleDomain(const string &domain) const {
    io_context ioContext;
    vector<uint32_t> ips = st::utils::dns::query(domain);
    if (!dns.empty()) {
        vector<uint32_t> preferIPs = st::utils::dns::query(dns, domain);
        if (preferIPs.size() > 0) {
            ips = preferIPs;
        }
    }
    Logger::INFO << "resovle domain" << domain << st::utils::ipv4::ipsToStr(ips) << END;
    return ips;
}
