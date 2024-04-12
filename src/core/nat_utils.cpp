//
// Created by codingdie on 2020/10/5.
//

#include "nat_utils.h"
#include "config.h"
#include <arpa/inet.h>
#include <stdio.h>
#ifdef linux

#include <linux/netfilter_ipv4.h>

#endif

#ifdef __APPLE__

tcp::endpoint NATUtils::getDstAddrForMac(__uint32_t clientIp, __uint16_t clientPort, __uint32_t serverIp,
                                         __uint16_t serverPort) {
    uint32_t ip = 0;
    uint16_t port = 0;
    struct pfioc_natlook pnl;
    memset(&pnl, 0, sizeof(pnl));
    pnl.proto = IPPROTO_TCP;
    pnl.direction = PF_OUT;
    pnl.af = AF_INET;
    pnl.saddr.pfa._addr32[0] = htonl(clientIp);
    pnl.sxport.spi = htonl((clientPort * 1UL) << 16L);
    pnl.daddr.pfa._addr32[0] = htonl(serverIp);
    pnl.dxport.spi = htonl((serverPort * 1UL) << 16L);
    if (pffd) {
        int result = ioctl(pffd, DIOCNATLOOK, &pnl);
        if (result) {
            logger::ERROR << "ioctl(DIOCNATLOOK):" << strerror(errno) << logger::ENDL;
        } else {
            ip = ntohl(pnl.rdaddr.v4addr.s_addr);
            port = ntohs(pnl.rdxport.port);
        }
    } else {
        logger::ERROR << "can't open /dev/pf" << strerror(errno) << logger::ENDL;
    }

    return move(tcp::endpoint(make_address_v4(ip), port));
}

#endif


nat_utils &nat_utils::uniq() {
    static nat_utils vp;
    return vp;
}
tcp::endpoint nat_utils::getProxyAddr(boost::asio::ip::tcp::socket &socket) {
#ifdef __APPLE__
    boost::system::error_code ec;
    auto clientEnd = socket.remote_endpoint(ec);
    if (!ec) {
        auto serverEnd = socket.local_endpoint(ec);
        if (!ec) {
            return move(getDstAddrForMac(clientEnd.address().to_v4().to_uint(), clientEnd.port(),
                                         serverEnd.address().to_v4().to_uint(), serverEnd.port()));
        } else {
            logger::ERROR << __PRETTY_FUNCTION__ << "get server addr failed!" << ec.message() << END;
        }
    } else {
        logger::ERROR << __PRETTY_FUNCTION__ << "get client addr failed!" << ec.message() << END;
    }
#endif

#ifdef linux
    int fd = socket.native_handle();
    sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(sockaddr_storage));
    socklen_t socklen = sizeof(destaddr);
    int error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &destaddr, &socklen);
    if (!error) {
        char ipstr[INET_ADDRSTRLEN];
        uint16_t port;
        auto *sa = (sockaddr_in *) &destaddr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
        port = ntohs(sa->sin_port);
        return ip::tcp::endpoint(make_address_v4(ipstr), port);
    }
#endif
    return ip::tcp::endpoint(make_address_v4("0.0.0.0"), 0);
}

nat_utils::nat_utils() {
    openwrt = file::exists("/etc/openwrt_release");
#ifdef __APPLE__
    pffd = open("/dev/pf", O_RDWR | O_CLOEXEC);
#endif
}

bool nat_utils::add_whitelist_ip(uint32_t ips) { return add_to_ip_set("st-proxy-whitelist", ips); }

bool nat_utils::add_proxy_ip(uint32_t ips) { return add_to_ip_set("st-proxy-list", ips); }

bool nat_utils::add_test_domain(string domain) { return add_to_ip_set("st-proxy-test", domain); }

bool nat_utils::add_to_ip_set(string name, string domain) {
    bool result = true;
    for (auto ip : st::utils::dns::query(domain)) {
        result &= add_to_ip_set(name, ip);
    }
    return result;
}
bool nat_utils::add_to_ip_set(string name, uint32_t ips) {
    string result;
    string error;
#ifdef __APPLE__
    bool success = shell::exec("pfctl -t " + name + " -T add " + ipv4::ip_to_str(ip), result, error);
#endif
#ifdef linux
    auto command = string(openwrt ? "" : "sudo ") + "/usr/sbin/ipset add -! " + name + " " + ipv4::ip_to_str(ips);
    bool success = shell::exec(command, result, error);
#endif
    if (!success) {
        logger::ERROR << "add_to_ip_set error!" << name << ipv4::ip_to_str(ips) << error << END;
    } else {
        logger::DEBUG << "add_to_ip_set success!" << name << ipv4::ip_to_str(ips) << result << END;
    }
    return success;
}


void nat_utils::set_mark(uint32_t mark, tcp::socket &socket) {
    int fd = socket.native_handle();
    int error = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (error == -1) {
        logger::ERROR << "set mark error" << strerror(errno) << logger::ENDL;
    }
}


uint32_t nat_utils::get_mark(int fd) {
    uint32_t mark = 0;
    socklen_t len = sizeof(mark);
    int error = getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &len);
    if (error != -1) {
        return mark;
    }
    return -1;
}


bool nat_utils::add_nat_whitelist() {
    for (auto ip : st::proxy::config::uniq().ip_whitelist) {
        if (!nat_utils::uniq().add_whitelist_ip(ip)) {
            return false;
        }
        logger::INFO << "add nat whitelist" << ipv4::ip_to_str(ip) << END;
    }
    return true;
}


bool nat_utils::intercept_nat_traffic(bool intercept) {
    if (intercept) {
        if (!add_nat_whitelist()) {
            return false;
        }
    }
    auto &targets = st::proxy::config::uniq().proxy_target;
    string proxy_dist_port;
    if (targets.find("all") == targets.end()) {
        if (targets.find("dns") != targets.end()) {
            proxy_dist_port += "53,853,";
        }
        if (targets.find("http") != targets.end()) {
            proxy_dist_port += "80,443,";
        }
    }
    if (!proxy_dist_port.empty()) {
        proxy_dist_port = proxy_dist_port.substr(0, proxy_dist_port.size() - 1);
    }
    string command = string(openwrt ? "" : "sudo ") + "sh " + st::proxy::config::uniq().base_conf_dir +
                     "/nat/rule.sh " + (intercept ? "intercept" : "clean") + " " + proxy_dist_port;
    string result;
    string error;
    if (shell::exec(command, result, error)) {
        return true;
    } else {
        logger::ERROR << "intercept nat traffic error!" << error << END;
        return false;
    }
}
