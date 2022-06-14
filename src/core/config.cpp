//
// Created by codingdie on 2020/6/30.
//

#include "config.h"

using namespace st::proxy;
using namespace st::utils;
config config::INSTANCE;

void config::load(const string &configPathInput) {
    baseConfDir = boost::filesystem::absolute(configPathInput).normalize().string();
    string configPath = configPathInput + "/config.json";
    if (st::utils::file::exit(configPath)) {
        ptree tree;
        try {
            read_json(configPath, tree);
        } catch (json_parser_error &e) {
            logger::ERROR << " parse config file " + configPath + " error!" << e.message() << END;
            exit(1);
        }
        this->ip = tree.get("ip", string(this->ip));
        this->port = stoi(tree.get("port", to_string(this->port)));
        this->so_timeout = stoi(tree.get("so_timeout", to_string(this->so_timeout)));
        this->connect_timeout = stoi(tree.get("connect_timeout", to_string(this->connect_timeout)));
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
                stream_tunnel *streamTunnel = parseStreamTunnel(it->second);
                tunnels.emplace_back(streamTunnel);
            }
        }
        logger::init(tree);

    } else {
        logger::INFO << "st-proxy config file not exit!" << configPath << END;
        exit(1);
    }
}
set<uint32_t> config::parseWhitelistToIPs(const set<string> &domains) const {
    set<uint32_t> result;
    for (auto domain : domains) {
        if (st::utils::ipv4::str_to_ip(domain) > 0) {
            result.emplace(st::utils::ipv4::str_to_ip(domain));
        } else {
            if (domain[0] == '*') {
                continue;
            }
            auto ips = resovleDomain(domain);
            if (ips.empty()) {
                logger::ERROR << "resovle domains to ip failed!" << domain << domain << END;
                exit(1);
            }
            for (auto ipTmp : ips) {
                result.emplace(ipTmp);
            }
        }
    }
    return result;
}

template<class K, class D, class C>
stream_tunnel *config::parseStreamTunnel(basic_ptree<K, D, C> &tunnel) const {
    string type = tunnel.get("type", "DIRECT");
    if (type.empty()) {
        logger::ERROR << "tunnel type empty!" << END;
        exit(1);
    }
    string serverIp = tunnel.get("ip", "");
    int tunnelPort = tunnel.get("port", 0);
    if (type != "DIRECT") {
        if (serverIp.empty()) {
            logger::ERROR << "tunnel ip empty!" << END;
            exit(1);
        }
        if (tunnelPort <= 0) {
            logger::ERROR << "tunnel port empty!" << END;
            exit(1);
        }
    }

    auto streamTunnel = new stream_tunnel(type, serverIp, tunnelPort);
    streamTunnel->area = tunnel.get("area", "");
    boost::optional<basic_ptree<K, D, C> &> areaListNode = tunnel.get_child_optional("proxy_areas");
    if (areaListNode.is_initialized()) {
        basic_ptree<K, D, C> arealistArr = areaListNode.get();
        for (boost::property_tree::ptree::value_type &v : arealistArr) {
            string area = v.second.get_value<string>();
            streamTunnel->proxyAreas.emplace_back(area);
        }
    }
    if (streamTunnel->area.length() > 0) {
        streamTunnel->proxyAreas.insert(streamTunnel->proxyAreas.begin(), streamTunnel->area);
    }
    for (auto &area : streamTunnel->proxyAreas) {
        if (!st::areaip::manager::uniq().load_area_ips(area)) {
            exit(1);
        }
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
vector<uint32_t> config::resovleDomain(const string &domain) const {
    io_context ioContext;
    vector<uint32_t> ips = st::utils::dns::query(domain);
    if (!dns.empty()) {
        vector<uint32_t> preferIPs = st::utils::dns::query(dns, domain);
        if (!preferIPs.empty()) {
            ips = preferIPs;
        }
    }
    logger::INFO << "resovle domain" << domain << st::utils::ipv4::ips_to_str(ips) << END;
    return ips;
}
