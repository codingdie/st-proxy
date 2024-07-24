//
// Created by codingdie on 24-4-12.
//

#include "proxy_console.h"
#include "analyzer/quality_analyzer.h"
#include "command/dns_command.h"
#include "config.h"
#include "virtual_port_manager.h"
void proxy_console::start() {
    console =
            new st::console::udp_console(st::proxy::config::uniq().console_ip, st::proxy::config::uniq().console_port);
    console->desc.add_options()("ip", boost::program_options::value<string>()->default_value(""), "ip");
    console->desc.add_options()("port", boost::program_options::value<uint16_t>()->default_value(443), "port");
    console->desc.add_options()("domain", boost::program_options::value<string>()->default_value(""), "domain");
    console->desc.add_options()("area", boost::program_options::value<string>()->default_value(""), "area");
    console->impl = [this](const vector<string> &commands, const boost::program_options::variables_map &options) {
        auto command = utils::strutils::join(commands, " ");
        std::pair<bool, std::string> result = make_pair(false, "not invalid command");
        string domain = options["domain"].as<string>();
        string area = options["area"].as<string>();
        string ipStr = options["ip"].as<string>();
        uint32_t ip = 0;
        uint16_t port = options["port"].as<uint16_t>();
        if (!ipStr.empty()) {
            ip = ipv4::str_to_ip(ipStr);
        }
        if (command == "proxy analyse ip tunnels" && ip > 0) {
            return make_pair(true, analyse_ip_tunnels(ip));
        } else if (command == "proxy analyse ip" && ip > 0) {
            return make_pair(true, analyse_ip(ip));
        } else if (command == "proxy analyse tunnel") {
            return make_pair(true, analyse_tunnel());
        } else if (command == "proxy analyse delete") {
            if (!domain.empty()) {
                quality_analyzer::uniq().delete_record(domain);
                return make_pair(false, string(domain));
            }
            if (ip > 0) {
                quality_analyzer::uniq().delete_record(ip);
                return make_pair(false, ipStr);
            }
        } else if (command == "proxy analyse delete all") {
            quality_analyzer::uniq().delete_all_record();
            return make_pair(true, string("delete all!"));

        } else if (command == "proxy blacklist") {
            string str;
            //            vector<std::string> ips = st::proxy::shm::uniq().forbid_ip_list();
            //            for (const auto &blackIp : ips) {
            //                auto domains = st::dns::shm::share().reverse_resolve_all(ipv4::str_to_ip(blackIp));
            //                str.append(blackIp).append("\t").append(join(domains, ",")).append("\n");
            //            }
            strutils::trim(str);
            return make_pair(true, str);
        } else if (command == "proxy register area virtual port") {
            if (ip > 0 && port > 0 && !area.empty()) {
                uint16_t virtual_port = virtual_port_manager::uniq().register_area_virtual_port(ip, port, area);
                return make_pair(true, to_string(virtual_port));
            }
        }
        return result;
    };
    console->start();
}

string proxy_console::analyse_ip_tunnels(uint32_t ip) {
    string str;
    auto tunnels = quality_analyzer::uniq().select_tunnels(ip, 0, st::command::dns::reverse_resolve(ip), "");
    int i = 0;
    for (auto &it : tunnels) {
        auto tunnel = it.first;
        const auto &tunnel_record = it.second.second;
        str.append(to_string(i++))
                .append("\t")
                .append(tunnel->id())
                .append("\t")
                .append(tunnel->area)
                .append("\t")
                .append(to_string(it.second.first))
                .append("\t")
                .append(to_string(tunnel_record.first_package_success()))
                .append("\t")
                .append(to_string(tunnel_record.first_package_failed()))
                .append("\t")
                .append(to_string(tunnel_record.first_package_cost()))
                .append("\n");
    }
    strutils::trim(str);
    return str;
}

string proxy_console::analyse_tunnel() {
    string str;
    unordered_map<string, st::proxy::proto::quality_record> result;
    for (const auto &tunnel : proxy::config::uniq().tunnels) {
        auto record = quality_analyzer::uniq().get_tunnel_record(tunnel->id());
        vector<string> failed_ips;
        for (const auto &item : record.records()) {
            if (!item.success()) {
                failed_ips.emplace_back(ipv4::ip_to_str(item.ip()));
            }
        }
        str.append(tunnel->id())
                .append("\t")
                .append(tunnel->area)
                .append("\t")
                .append(to_string(record.first_package_success()))
                .append("\t")
                .append(to_string(record.first_package_failed()))
                .append("\t")
                .append(to_string(record.first_package_cost()))
                .append("\t")
                .append(join(failed_ips, ","))
                .append("\n");
    }
    strutils::trim(str);
    return str;
}
string proxy_console::analyse_ip(uint32_t ip) {
    string str;
    auto ip_record = quality_analyzer::uniq().get_ip_record(ip);
    str.append(utils::ipv4::ip_to_str(ip))
            .append("\t")
            .append(to_string(ip_record.first_package_success()))
            .append("\t")
            .append(to_string(ip_record.first_package_failed()))
            .append("\t")
            .append(to_string(ip_record.first_package_cost()))
            .append("\n");
    strutils::trim(str);
    return str;
}
proxy_console::proxy_console() {}
void proxy_console::shutdown() {
    if (console != nullptr) {
        delete console;
        console = nullptr;
    }
}
proxy_console::~proxy_console() { shutdown(); }
