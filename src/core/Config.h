//
// Created by codingdie on 2020/6/30.
//

#ifndef ST_PROXY_CONFIG_H
#define ST_PROXY_CONFIG_H

#include "StreamTunnel.h"
#include "utils/STUtils.h"
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
        class Config {
        public:
            static Config INSTANCE;
            string ip = "127.0.0.1";
            int port = 40000;
            int soTimeout = 60000;
            int connectTimeout = 10000;
            string baseConfDir = "/etc/st/proxy";
            vector<StreamTunnel *> tunnels;
            int parallel = 16;
            string dns = "";
            vector<string> whitelist;
            Config() = default;

            void load(const string &configPathInput);
            template<class K, class D, class C>
            StreamTunnel *parseStreamTunnel(basic_ptree<K, D, C> &tunnel) const;
        };
    };// namespace proxy
}// namespace st
#endif//ST_PROXY_CONFIG_H
