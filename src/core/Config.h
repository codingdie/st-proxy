//
// Created by codingdie on 2020/6/30.
//

#ifndef ST_PROXY_CONFIG_H
#define ST_PROXY_CONFIG_H

#include "STStreamTunnel.h"
#include "utils/STUtils.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace std;
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
            vector<STStreamTunnel *> tunnels;
            int logLevel = 2;
            int parallel = 16;
            string dns = "";
            Config() = default;

            void load(const string &configPathInput) {
                baseConfDir = boost::filesystem::absolute(configPathInput).normalize().string();
                string configPath = configPathInput + "/config.json";
                if (st::utils::file::exit(configPath)) {
                    ptree tree;
                    try {
                        read_json(configPath, tree);
                    } catch (json_parser_error e) {
                        Logger::ERROR << " parse config file " + configPath + " error!"
                                      << e.message() << END;
                        exit(1);
                    }
                    this->ip = tree.get("ip", string(this->ip));
                    this->logLevel = stoi(tree.get("log", to_string(this->logLevel)));
                    Logger::LEVEL = this->logLevel;
                    this->port = stoi(tree.get("port", to_string(this->port)));
                    this->soTimeout = stoi(tree.get("so_timeout", to_string(this->soTimeout)));
                    this->connectTimeout =
                            stoi(tree.get("connect_timeout", to_string(this->connectTimeout)));
                    this->parallel = stoi(tree.get("parallel", to_string(this->parallel)));
                    this->dns = tree.get("dns", string(this->dns));

                    auto tunnelNodes = tree.get_child("tunnels");
                    if (!tunnelNodes.empty()) {
                        for (auto it = tunnelNodes.begin(); it != tunnelNodes.end(); it++) {
                            STStreamTunnel *streamTunnel = parseStreamTunnel(it->second);
                            tunnels.emplace_back(streamTunnel);
                        }
                    }
                } else {
                    Logger::INFO << "st-proxy config file not exit!" << configPath << END;
                    exit(1);
                }
            }

            template<class K, class D, class C>
            STStreamTunnel *parseStreamTunnel(basic_ptree<K, D, C> &tunnel) const {
                string type = tunnel.get("type", "DIRECT");
                string area = tunnel.get("area", "");
                bool onlyAreaIp = tunnel.get("only_area_ip", false);
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
                STStreamTunnel *streamTunnel =
                        new STStreamTunnel(type, serverIp, serverPort, area, onlyAreaIp);
                string realServerHost = tunnel.get("real_server_host", "");
                vector<std::string> whitelist = strutils::split(tunnel.get("whitelist", ""), ",");
                streamTunnel->realServerHost = realServerHost;
                streamTunnel->whitelistHosts = whitelist;
                streamTunnel->priority = tunnel.get("priority", 0);
                return streamTunnel;
            }
        };

    }// namespace proxy
}// namespace st


#endif//ST_PROXY_CONFIG_H
