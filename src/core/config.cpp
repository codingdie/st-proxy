//
// Created by codingdie on 2020/6/30.
//

#include "config.h"
#include "quality_analyzer.h"
using namespace st::proxy;
using namespace st::utils;
void config::load(const string &configPathInput) {
    base_conf_dir = boost::filesystem::absolute(configPathInput).normalize().string();
    string configPath = configPathInput + "/config.json";
    if (st::utils::file::exit(configPath)) {
        ptree tree;
        try {
            read_json(configPath, tree);
        } catch (json_parser_error &e) {
            logger::ERROR << " parse config file " + configPath + " error!" << e.message() << END;
            exit(1);
        }
        this->ip = tree.get("ip", this->ip);
        this->port = stoi(tree.get("port", to_string(this->port)));
        this->console_ip = tree.get("console_ip", console_ip);
        this->console_port = tree.get("console_port", console_port);
        this->so_timeout = stoi(tree.get("so_timeout", to_string(this->so_timeout)));
        this->connect_timeout = stoi(tree.get("connect_timeout", to_string(this->connect_timeout)));
        this->dns = tree.get("dns", string(this->dns));
        auto proxy_target_node = tree.get_child_optional("proxy_target");
        if (proxy_target_node.is_initialized()) {
            auto proxy_target_arr = proxy_target_node.get();
            for (boost::property_tree::ptree::value_type &v : proxy_target_arr) {
                auto target = v.second.get_value<string>();
                this->proxy_target.emplace(target);
            }
        }
        auto whitelistNode = tree.get_child_optional("whitelist");
        if (whitelistNode.is_initialized()) {
            auto whitelistArr = whitelistNode.get();
            for (boost::property_tree::ptree::value_type &v : whitelistArr) {
                auto domain = v.second.get_value<string>();
                this->whitelist.emplace(domain);
            }
        }
        auto tunnelNodes = tree.get_child("tunnels");
        if (!tunnelNodes.empty()) {
            for (auto it = tunnelNodes.begin(); it != tunnelNodes.end(); it++) {
                stream_tunnel *streamTunnel = parse_stream_tunnel(it->second);
                tunnels.emplace_back(streamTunnel);
            }
        }
        parse_whitelist_to_ips();
        logger::init(tree);
    } else {
        logger::INFO << "st-proxy config file not exit!" << configPath << END;
        exit(1);
    }
}
set<uint32_t> config::parse_whitelist_to_ips(const set<string> &domains) const {
    set<uint32_t> result;
    for (auto domain : domains) {
        if (st::utils::ipv4::str_to_ip(domain) > 0) {
            result.emplace(st::utils::ipv4::str_to_ip(domain));
        } else {
            if (domain[0] == '*') {
                continue;
            }
            auto ips = resolve_domain(domain);
            if (ips.empty()) {
                logger::WARN << "resolve domains to ip failed!" << domain << domain << END;
            }
            for (auto ipTmp : ips) {
                result.emplace(ipTmp);
            }
        }
    }
    return result;
}

template<class K, class D, class C>
stream_tunnel *config::parse_stream_tunnel(basic_ptree<K, D, C> &tunnel) const {
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

    auto st = new stream_tunnel(type, serverIp, tunnelPort);
    st->area = tunnel.get("area", "");
    st->http_check_url = tunnel.get("http_check_url", "");
    boost::optional<basic_ptree<K, D, C> &> areaListNode = tunnel.get_child_optional("proxy_areas");
    if (areaListNode.is_initialized()) {
        basic_ptree<K, D, C> arealistArr = areaListNode.get();
        for (boost::property_tree::ptree::value_type &v : arealistArr) {
            string area = v.second.get_value<string>();
            st->proxyAreas.emplace_back(area);
        }
    }
    if (st->area.length() > 0) {
        st->proxyAreas.insert(st->proxyAreas.begin(), st->area);
    }
    for (auto &area : st->proxyAreas) {
        if (!st::areaip::manager::uniq().load_area_ips(area)) {
            exit(1);
        }
    }

    boost::optional<basic_ptree<K, D, C> &> whitelistNode = tunnel.get_child_optional("whitelist");
    if (whitelistNode.is_initialized()) {
        basic_ptree<K, D, C> whitelistArr = whitelistNode.get();
        for (boost::property_tree::ptree::value_type &v : whitelistArr) {
            string domain = v.second.get_value<string>();
            st->whitelist.emplace(domain);
        }
    }
    return st;
}
vector<uint32_t> config::resolve_domain(const string &domain) const {
    vector<uint32_t> ips = st::utils::dns::query(domain);
    if (!dns.empty()) {
        vector<uint32_t> results = st::utils::dns::query(dns, domain);
        if (!results.empty()) {
            ips = results;
        }
    }
    return ips;
}
config &config::uniq() {
    static config INSTANCE;
    return INSTANCE;
}
void config::parse_whitelist_to_ips() {
    this->ip_whitelist = parse_whitelist_to_ips(this->whitelist);
    for (auto &tunnel : this->tunnels) {
        tunnel->ip_whitelist = parse_whitelist_to_ips(tunnel->whitelist);
    }
}
