//
// Created by codingdie on 2020/6/27.
//
#include "ProxyServer.h"

int main(int argc, char *argv[]) {
    auto v1 = st::utils::dns::query("114.114.114.114", "google.com");
    Logger::INFO << st::utils::ipv4::ipsToStr(v1) << END;
    auto v2 = st::utils::dns::query("192.168.31.1", "google.com");
    Logger::INFO << st::utils::ipv4::ipsToStr(v2) << END;
    auto v3 = st::utils::dns::query("google.com");
    Logger::INFO << st::utils::ipv4::ipsToStr(v3) << END;

    // byte writeProxyBuffer[1024];
    // byte readProxyBuffer[1024];

    // boost::asio::io_context::work ioContextWork(ioContext);
    // tcp::socket proxySock(ioContext);
    // thread a([&]() { ioContext.run(); });
    // auto proxyEnd = tcp::endpoint(make_address_v4("127.0.0.1"), 1080);
    // auto distEnd = tcp::endpoint(make_address_v4("8.8.8.8"), 853);

    // auto connectFuture = proxySock.async_connect(
    //         proxyEnd, use_future([&](boost::system::error_code error) {
    //             if (error) {
    //                 Logger::ERROR << "proxy connect" << asio::addrStr(proxyEnd) << "failed!"
    //                               << error.message() << END;
    //                 return false;
    //             } else {
    //                 Logger::INFO << "proxy connect" << asio::addrStr(proxyEnd) << "success!" << END;
    //                 return true;
    //             }
    //         }));
    // future_status connectStatus = connectFuture.wait_for(std::chrono::milliseconds(500));
    // if (connectStatus != std::future_status::ready || connectFuture.get() == false) {
    //     if (connectStatus != std::future_status::ready) {
    //         Logger::ERROR << "proxy connect" << asio::addrStr(proxyEnd) << " timeout" << END;
    //     }
    // } else {
    //     writeProxyBuffer[0] = 0x05;
    //     writeProxyBuffer[1] = 0x01;
    //     writeProxyBuffer[2] = 0x00;
    //     auto sendStep1Future = proxySock.async_send(
    //             buffer(writeProxyBuffer, sizeof(byte) * 3),
    //             use_future([&](boost::system::error_code error, size_t size) { return !error; }));
    //     future_status sendStep1Status = sendStep1Future.wait_for(std::chrono::milliseconds(100));
    //     if (sendStep1Status != std::future_status::ready || sendStep1Future.get() == false) {
    //         if (connectStatus != std::future_status::ready) {
    //             Logger::ERROR << "proxy connect handshake client 01" << asio::addrStr(proxyEnd)
    //                           << " timeout" << END;
    //         }
    //     } else {
    //         auto receiveStep1Future =
    //                 proxySock.async_receive(buffer(readProxyBuffer, sizeof(byte) * 2),
    //                                         use_future([&](boost::system::error_code error,
    //                                                        size_t size) { return !error; }));
    //         future_status receiveStep1Status =
    //                 receiveStep1Future.wait_for(std::chrono::milliseconds(100));
    //         if (receiveStep1Status != std::future_status::ready ||
    //             receiveStep1Future.get() == false) {
    //             if (connectStatus != std::future_status::ready) {
    //                 Logger::ERROR << "proxy connect handshake server 01" << asio::addrStr(proxyEnd)
    //                               << " timeout" << END;
    //             }
    //         } else {
    //             if (readProxyBuffer[0] == 0x05 && readProxyBuffer[1] == 0x00) {
    //                 writeProxyBuffer[0] = 0x05;
    //                 writeProxyBuffer[1] = 0x01;
    //                 writeProxyBuffer[2] = 0x00;
    //                 writeProxyBuffer[3] = 0x01;
    //                 auto ipArray = distEnd.address().to_v4().to_bytes();
    //                 writeProxyBuffer[4] = ipArray[0];
    //                 writeProxyBuffer[5] = ipArray[1];
    //                 writeProxyBuffer[6] = ipArray[2];
    //                 writeProxyBuffer[7] = ipArray[3];
    //                 uint16_t port = distEnd.port();
    //                 writeProxyBuffer[8] = (port >> 8) & 0XFF;
    //                 writeProxyBuffer[9] = port & 0XFF;
    //                 auto sendStep2Future =
    //                         proxySock.async_send(buffer(writeProxyBuffer, sizeof(byte) * 10),
    //                                              use_future([&](boost::system::error_code error,
    //                                                             size_t size) { return !error; }));
    //                 future_status sendStep2Status =
    //                         sendStep2Future.wait_for(std::chrono::milliseconds(100));
    //                 if (sendStep2Status != std::future_status::ready ||
    //                     sendStep2Future.get() == false) {
    //                 } else {
    //                     auto receiveStep2Future = proxySock.async_receive(
    //                             buffer(readProxyBuffer, sizeof(byte) * 2),
    //                             use_future([&](boost::system::error_code error, size_t size) {
    //                                 return !error;
    //                             }));
    //                     future_status receiveStep2Status =
    //                             receiveStep2Future.wait_for(std::chrono::milliseconds(1000));
    //                     if (receiveStep2Status != std::future_status::ready ||
    //                         receiveStep2Future.get() == false) {
    //                         if (connectStatus != std::future_status::ready) {
    //                             Logger::ERROR << "proxy connect handshake server 01"
    //                                           << asio::addrStr(proxyEnd) << " timeout" << END;
    //                         }
    //                     } else {
    //                         Logger::ERROR << "proxy connect handshake server 01"
    //                                       << asio::addrStr(proxyEnd) << " timeout" << END;
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }

    // a.join();

    return 0;
}
