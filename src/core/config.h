//
// Created by codingdie on 2020/6/30.
//

#ifndef ST_PROXY_CONFIG_H
#define ST_PROXY_CONFIG_H

#include "st.h"
#include "stream_tunnel.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional/optional.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace boost::property_tree;
using namespace std;
using namespace boost::asio;

namespace st {
    namespace proxy {
        class config {
        public:
            string ip = "127.0.0.1";
            int port = 40000;
            string console_ip = "127.0.0.1";
            int console_port = 5858;
            int so_timeout = 60000;
            int connect_timeout = 10000;
            string baseConfDir = "/etc/st/proxy";
            vector<stream_tunnel *> tunnels;
            string dns = "";
            set<string> whitelist;
            set<uint32_t> whitelistIPs;
            config() = default;
            static config &uniq();
            void load(const string &configPathInput);
            vector<uint32_t> resolve_domain(const string &domain) const;

        private:
            template<class K, class D, class C>
            stream_tunnel *parseStreamTunnel(basic_ptree<K, D, C> &tunnel) const;
            set<uint32_t> parse_whitelist_to_ips(const set<string> &domains) const;
        };
    };// namespace proxy
}// namespace st
#endif//ST_PROXY_CONFIG_H
