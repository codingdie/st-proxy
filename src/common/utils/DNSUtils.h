#ifndef DNSUTILS_H
#define DNSUTILS_H

#include "IPUtils.h"
#include "ShellUtils.h"
#include "StringUtils.h"
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <string>
#include <vector>
#include "Logger.h"

using namespace boost::asio;
using namespace std;
namespace st {
    namespace utils {
        namespace dns {
            static inline vector<uint32_t> query(const string &dnsServer, const string &host) {
                string error;
                string result;
                vector<uint32_t> resultIPs;
                auto cm = "nslookup " + host + "  " + dnsServer;
                auto success = st::utils::shell::exec(cm, result, error);
                if (success && !result.empty()) {
                    bool nameLine = false;
                    for (auto &str : st::utils::str::split(result, "\n")) {
                        if (nameLine && str.find("Address") != string::npos) {
                            string ipStr = st::utils::str::split(str, ":")[1];
                            boost::trim(ipStr);
                            resultIPs.emplace_back(st::utils::ipv4::strToIp(ipStr));
                        }
                        nameLine = str.find("Name:") != string::npos &&
                                   str.find(host) != string::npos;
                    }
                }
                if (resultIPs.empty()) {
                    if (!result.empty()){
                        Logger::INFO << result << END;
                    }
                    if (!error.empty()) {
                        Logger::ERROR << error << END;
                    }
                }
                return resultIPs;
            }
            static inline vector<uint32_t> query(const string &host) {
                vector<uint32_t> resultIPs;

                boost::asio::io_context ctx;
                ip::udp::resolver slv(ctx);
                ip::udp::resolver::query qry(host, "");
                boost::system::error_code error;
                ip::udp::resolver::iterator ipIt = slv.resolve(qry, error);
                ip::udp::resolver::iterator end;
                for (; ipIt != end; ipIt++) {
                    auto ip = (*ipIt).endpoint().address().to_v4().to_uint();
                    resultIPs.emplace_back(ip);
                }
                return resultIPs;
            }
        }// namespace dns
    }    // namespace utils
}// namespace st

#endif
