//
// Created by codingdie on 24-4-12.
//

#include "proxy_console.h"
#include "analyzer/net_test_manager.h"
#include "analyzer/quality_analyzer.h"
#include "command/dns_command.h"
#include "config.h"
#include "virtual_port_manager.h"
#include "session_manager.h"
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
            vector<uint32_t> ips = quality_analyzer::uniq().get_blacklist_ips();
            for (const auto &blackIp : ips) {
                auto domains = st::command::dns::reverse_resolve(blackIp);
                str.append(ipv4::ip_to_str(blackIp)).append("\t").append(strutils::join(domains, ",")).append("\n");
            }
            strutils::trim(str);
            return make_pair(true, str);
        } else if (command == "proxy register area virtual port") {
            if (ip > 0 && port > 0 && !area.empty()) {
                uint16_t virtual_port = virtual_port_manager::uniq().register_area_virtual_port(ip, port, area);
                return make_pair(true, to_string(virtual_port));
            }
        } else if (command == "proxy ip available areas") {
            if (ip > 0) {
                string str;
                auto tunnels =
                        quality_analyzer::uniq().select_tunnels(ip, 0, st::command::dns::reverse_resolve(ip), "");
                unordered_set<string> areas;
                for (auto &it : tunnels) {
                    auto tunnel = it.first;
                    const auto &tunnel_record = it.second.second;
                    if (tunnel_record.first_package_success() == 0 && tunnel_record.first_package_failed() > 0) {
                        continue;
                    }
                    areas.emplace(tunnel->area);
                }
                return make_pair(true, strutils::join(areas, ","));
            }
        } else if (command == "proxy net test list") {
            const auto &current_all_test = net_test_manager::uniq().current_all_test();
            vector<string> lines(current_all_test.size());
            std::transform(current_all_test.begin(), current_all_test.end(), lines.begin(),
                           [](task::priority_task<test_case> task) {
                               {
                                   std::stringstream ss;
                                   ss << task.id << '\t' << task.priority << '\t' << task.status << '\t'
                                      << task.create_time << '\t' << task.in.key() << '\t' << task.pk;
                                   return ss.str();
                               }
                           });

            return make_pair(true, strutils::join(lines, "\n"));
        } else if (command == "proxy session list") {
            return make_pair(true, strutils::join(session_manager::uniq().status(), "\n"));
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
        int64_t expire_minutes = quality_analyzer::get_min_expire_minutes(tunnel_record);
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
                .append("\t")
                .append(expire_minutes >= 0 ? to_string(expire_minutes) : "-")
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
        int64_t expire_minutes = quality_analyzer::get_min_expire_minutes(record);
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
                .append("\t")
                .append(expire_minutes >= 0 ? to_string(expire_minutes) : "-")
                .append("\n");
    }
    strutils::trim(str);
    return str;
}
string proxy_console::analyse_ip(uint32_t ip) {
    string str;
    auto ip_record = quality_analyzer::uniq().get_ip_record(ip);
    int64_t expire_minutes = quality_analyzer::get_min_expire_minutes(ip_record);
    str.append(utils::ipv4::ip_to_str(ip))
            .append("\t")
            .append(to_string(ip_record.first_package_success()))
            .append("\t")
            .append(to_string(ip_record.first_package_failed()))
            .append("\t")
            .append(to_string(ip_record.first_package_cost()))
            .append("\t")
            .append(expire_minutes >= 0 ? to_string(expire_minutes) : "-")
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
