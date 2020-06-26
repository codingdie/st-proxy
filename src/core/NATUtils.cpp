//
// Created by codingdie on 2020/10/5.
//

#include "NATUtils.h"
#include <arpa/inet.h>
#include <stdio.h>

#ifdef linux

#include <linux/netfilter_ipv4.h>

#endif

#ifdef __APPLE__

tcp::endpoint NATUtils::getDstAddrForMac(__uint32_t clientIp, __uint16_t clientPort,
                                         __uint32_t serverIp, __uint16_t serverPort) {
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
            Logger::ERROR << "ioctl(DIOCNATLOOK):" << strerror(errno) << Logger::ENDL;
        } else {
            ip = ntohl(pnl.rdaddr.v4addr.s_addr);
            port = ntohs(pnl.rdxport.port);
        }
    } else {
        Logger::ERROR << "can't open /dev/pf" << strerror(errno) << Logger::ENDL;
    }

    return move(tcp::endpoint(make_address_v4(ip), port));
}

#endif


tcp::endpoint NATUtils::getProxyAddr(boost::asio::ip::tcp::socket &socket) {
#ifdef __APPLE__
    boost::system::error_code ec;
    auto clientEnd = socket.remote_endpoint(ec);
    if (!ec) {
        auto serverEnd = socket.local_endpoint(ec);
        if (!ec) {
            return move(getDstAddrForMac(clientEnd.address().to_v4().to_uint(), clientEnd.port(),
                                         serverEnd.address().to_v4().to_uint(), serverEnd.port()));
        } else {
            Logger::ERROR << __PRETTY_FUNCTION__ << "get server addr failed!" << ec.message()
                          << END;
        }
    } else {
        Logger::ERROR << __PRETTY_FUNCTION__ << "get client addr failed!" << ec.message() << END;
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

NATUtils::NATUtils() {
#ifdef __APPLE__
    pffd = open("/dev/pf", O_RDWR | O_CLOEXEC);
#endif
}

bool NATUtils::addToNatWhitelist(uint32_t ip) {
    string result;
    string error;
#ifdef __APPLE__
    bool success =
            shell::exec("pfctl -t st-proxy-whitelist -T add " + ipv4::ipToStr(ip), result, error);
#endif
#ifdef linux
    auto command = "/usr/sbin/ipset add -! st-proxy-tunnels " + ipv4::ipToStr(ip);
    Logger::INFO << command << END;
    bool success = shell::exec(command, result, error);
#endif
    if (!success) {
        Logger::ERROR << "addToNatWhitelist error!" << ipv4::ipToStr(ip) << error << END;
    } else {
        Logger::INFO << "addToNatWhitelist success!" << ipv4::ipToStr(ip) << result << END;
    }
    return success;
}


NATUtils NATUtils::INSTANCE;
