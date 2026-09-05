#include "config.h"
#include "nat_utils.h"
#include "proxy_server.h"
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace {

const char TEST_DESTINATION_IP[] = "198.18.0.1";
const uint16_t TEST_DESTINATION_PORT = 18080;
const string LOCAL_HTTP_RESPONSE = "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: text/plain\r\n"
                                   "Content-Length: 17\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "st-proxy-local-ok";

string test_runtime_dir() {
    const char *configured_runtime_dir = std::getenv("ST_RUNTIME_DIR");
    if (configured_runtime_dir != nullptr && configured_runtime_dir[0] != '\0') {
        return configured_runtime_dir;
    }
    return "/tmp/st-proxy-integration";
}

bool write_local_proxy_config(const uint16_t socks_port, string &config_dir) {
    config_dir = test_runtime_dir() + "/local-proxy-config";
    const string nat_dir = config_dir + "/nat";
    boost::system::error_code error;
    boost::filesystem::create_directories(nat_dir, error);
    if (error) {
        return false;
    }

    std::ifstream nat_rule_source("../confs/test/nat/rule.sh", std::ios::binary);
    std::ofstream nat_rule_target(nat_dir + "/rule.sh", std::ios::binary | std::ios::trunc);
    if (!nat_rule_source.is_open() || !nat_rule_target.is_open()) {
        return false;
    }
    nat_rule_target << nat_rule_source.rdbuf();

    std::ofstream config_file(config_dir + "/config.json", std::ios::trunc);
    if (!config_file.is_open()) {
        return false;
    }
    config_file << "{\n"
                << "  \"ip\": \"127.0.0.1\",\n"
                << "  \"port\": \"40000\",\n"
                << "  \"console_port\": 0,\n"
                << "  \"log\": {\"level\": 0, \"tag\": \"local-proxy-integration\"},\n"
                << "  \"tunnels\": [{\n"
                << "    \"type\": \"SOCKS\",\n"
                << "    \"ip\": \"127.0.0.1\",\n"
                << "    \"port\": " << socks_port << ",\n"
                << "    \"http_check_url\": \"http://127.0.0.1\",\n"
                << "    \"whitelist\": [\"" << TEST_DESTINATION_IP << "\"]\n"
                << "  }],\n"
                << "  \"so_timeout\": 3000,\n"
                << "  \"connect_timeout\": 3000,\n"
                << "  \"parallel\": 1,\n"
                << "  \"proxy_target\": [\"all\"]\n"
                << "}\n";
    return config_file.good();
}

class local_http_server {
public:
    local_http_server()
        : acceptor(context, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0)),
          worker(&local_http_server::serve, this) {}

    ~local_http_server() { stop(); }

    uint16_t port() const { return acceptor.local_endpoint().port(); }

    bool wait_for_completion(const std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(state_lock);
        return completed.wait_for(lock, timeout, [this]() { return finished; });
    }

    bool succeeded() const {
        std::lock_guard<std::mutex> lock(state_lock);
        return success;
    }

    string received_request() const {
        std::lock_guard<std::mutex> lock(state_lock);
        return request;
    }

private:
    void serve() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(context);
        {
            std::lock_guard<std::mutex> lock(socket_lock);
            active_socket = socket;
        }

        boost::system::error_code error;
        acceptor.accept(*socket, error);
        if (!error) {
            boost::asio::streambuf request_buffer;
            boost::asio::read_until(*socket, request_buffer, "\r\n\r\n", error);
            if (!error) {
                {
                    std::lock_guard<std::mutex> lock(state_lock);
                    request.assign(std::istreambuf_iterator<char>(&request_buffer), std::istreambuf_iterator<char>());
                }
                boost::asio::write(*socket, boost::asio::buffer(LOCAL_HTTP_RESPONSE), error);
            }
        }
        finish(!error);
    }

    void stop() {
        boost::system::error_code ignored_error;
        acceptor.close(ignored_error);
        std::shared_ptr<boost::asio::ip::tcp::socket> socket;
        {
            std::lock_guard<std::mutex> lock(socket_lock);
            socket = active_socket;
        }
        if (socket) {
            socket->shutdown(boost::asio::socket_base::shutdown_both, ignored_error);
            socket->close(ignored_error);
        }
        if (worker.joinable()) {
            worker.join();
        }
    }

    void finish(const bool result) {
        {
            std::lock_guard<std::mutex> lock(state_lock);
            success = result;
            finished = true;
        }
        completed.notify_all();
    }

    boost::asio::io_context context;
    boost::asio::ip::tcp::acceptor acceptor;
    std::thread worker;
    mutable std::mutex state_lock;
    std::condition_variable completed;
    bool finished = false;
    bool success = false;
    string request;
    std::mutex socket_lock;
    std::shared_ptr<boost::asio::ip::tcp::socket> active_socket;
};

class local_socks5_server {
public:
    explicit local_socks5_server(const uint16_t upstream_port)
        : upstream_port(upstream_port),
          acceptor(context, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0)),
          worker(&local_socks5_server::serve, this) {}

    ~local_socks5_server() { stop(); }

    uint16_t port() const { return acceptor.local_endpoint().port(); }

    bool wait_for_completion(const std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(state_lock);
        return completed.wait_for(lock, timeout, [this]() { return finished; });
    }

    bool succeeded() const {
        std::lock_guard<std::mutex> lock(state_lock);
        return success;
    }

    string requested_address() const {
        std::lock_guard<std::mutex> lock(state_lock);
        return requested_ip;
    }

    uint16_t requested_port() const {
        std::lock_guard<std::mutex> lock(state_lock);
        return destination_port;
    }

private:
    void serve() {
        auto client = std::make_shared<boost::asio::ip::tcp::socket>(context);
        {
            std::lock_guard<std::mutex> lock(socket_lock);
            client_socket = client;
        }

        boost::system::error_code error;
        acceptor.accept(*client, error);
        if (error) {
            finish(false);
            return;
        }

        std::array<unsigned char, 3> greeting{};
        boost::asio::read(*client, boost::asio::buffer(greeting), boost::asio::transfer_exactly(greeting.size()), error);
        if (error || greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00) {
            finish(false);
            return;
        }
        const std::array<unsigned char, 2> greeting_response{{0x05, 0x00}};
        boost::asio::write(*client, boost::asio::buffer(greeting_response), error);
        if (error) {
            finish(false);
            return;
        }

        std::array<unsigned char, 10> connect_request{};
        boost::asio::read(*client, boost::asio::buffer(connect_request), boost::asio::transfer_exactly(connect_request.size()), error);
        if (error || connect_request[0] != 0x05 || connect_request[1] != 0x01 || connect_request[3] != 0x01) {
            finish(false);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(state_lock);
            requested_ip = std::to_string(connect_request[4]) + "." + std::to_string(connect_request[5]) + "." +
                           std::to_string(connect_request[6]) + "." + std::to_string(connect_request[7]);
            destination_port = static_cast<uint16_t>((connect_request[8] << 8U) | connect_request[9]);
        }

        auto upstream = std::make_shared<boost::asio::ip::tcp::socket>(context);
        {
            std::lock_guard<std::mutex> lock(socket_lock);
            upstream_socket = upstream;
        }
        upstream->connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), upstream_port), error);
        if (error) {
            finish(false);
            return;
        }

        const std::array<unsigned char, 10> connect_response{{0x05, 0x00, 0x00, 0x01, 0x00,
                                                                0x00, 0x00, 0x00, 0x00, 0x00}};
        boost::asio::write(*client, boost::asio::buffer(connect_response), error);
        if (error) {
            finish(false);
            return;
        }

        boost::asio::streambuf request_buffer;
        boost::asio::read_until(*client, request_buffer, "\r\n\r\n", error);
        if (error) {
            finish(false);
            return;
        }
        const string request{std::istreambuf_iterator<char>(&request_buffer), std::istreambuf_iterator<char>()};
        boost::asio::write(*upstream, boost::asio::buffer(request), error);
        if (error) {
            finish(false);
            return;
        }

        std::vector<char> response(LOCAL_HTTP_RESPONSE.size());
        boost::asio::read(*upstream, boost::asio::buffer(response), boost::asio::transfer_exactly(response.size()), error);
        if (!error) {
            boost::asio::write(*client, boost::asio::buffer(response), error);
        }
        finish(!error);
    }

    void stop() {
        boost::system::error_code ignored_error;
        acceptor.close(ignored_error);
        std::shared_ptr<boost::asio::ip::tcp::socket> client;
        std::shared_ptr<boost::asio::ip::tcp::socket> upstream;
        {
            std::lock_guard<std::mutex> lock(socket_lock);
            client = client_socket;
            upstream = upstream_socket;
        }
        close_socket(client, ignored_error);
        close_socket(upstream, ignored_error);
        if (worker.joinable()) {
            worker.join();
        }
    }

    static void close_socket(const std::shared_ptr<boost::asio::ip::tcp::socket> &socket,
                             boost::system::error_code &ignored_error) {
        if (socket) {
            socket->shutdown(boost::asio::socket_base::shutdown_both, ignored_error);
            socket->close(ignored_error);
        }
    }

    void finish(const bool result) {
        {
            std::lock_guard<std::mutex> lock(state_lock);
            success = result;
            finished = true;
        }
        completed.notify_all();
    }

    const uint16_t upstream_port;
    boost::asio::io_context context;
    boost::asio::ip::tcp::acceptor acceptor;
    std::thread worker;
    mutable std::mutex state_lock;
    std::condition_variable completed;
    bool finished = false;
    bool success = false;
    string requested_ip;
    uint16_t destination_port = 0;
    std::mutex socket_lock;
    std::shared_ptr<boost::asio::ip::tcp::socket> client_socket;
    std::shared_ptr<boost::asio::ip::tcp::socket> upstream_socket;
};

class local_proxy_integration_test : public ::testing::Test {
protected:
    void SetUp() override {
        http_server.reset(new local_http_server());
        socks_server.reset(new local_socks5_server(http_server->port()));
        ASSERT_TRUE(write_local_proxy_config(socks_server->port(), config_dir));

        st::proxy::config::uniq().load(config_dir);
        proxy.reset(new proxy_server());
        proxy_thread = std::thread([this]() { proxy->start(); });
        proxy->wait_start();
        ASSERT_TRUE(nat_utils::uniq().add_to_ip_set("st-proxy-test", st::utils::ipv4::str_to_ip(TEST_DESTINATION_IP)));
    }

    void TearDown() override {
        if (proxy) {
            proxy->shutdown();
        }
        if (proxy_thread.joinable()) {
            proxy_thread.join();
        }
        st::proxy::config::uniq().unload();
        socks_server.reset();
        http_server.reset();
    }

    std::unique_ptr<local_http_server> http_server;
    std::unique_ptr<local_socks5_server> socks_server;
    std::unique_ptr<proxy_server> proxy;
    std::thread proxy_thread;
    string config_dir;
};

TEST_F(local_proxy_integration_test, routes_request_through_local_socks5_server) {
    boost::asio::io_context client_context;
    boost::asio::ip::tcp::socket client(client_context);
    boost::system::error_code error;
    client.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address_v4(TEST_DESTINATION_IP),
                                                   TEST_DESTINATION_PORT),
                   error);
    ASSERT_FALSE(error) << error.message();

    const string request = "GET /local-integration HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n";
    boost::asio::write(client, boost::asio::buffer(request), error);
    ASSERT_FALSE(error) << error.message();

    std::vector<char> response_buffer(LOCAL_HTTP_RESPONSE.size());
    boost::asio::read(client, boost::asio::buffer(response_buffer),
                      boost::asio::transfer_exactly(response_buffer.size()), error);
    ASSERT_FALSE(error) << error.message();
    const string response(response_buffer.begin(), response_buffer.end());

    ASSERT_NE(string::npos, response.find("st-proxy-local-ok"));
    ASSERT_TRUE(socks_server->wait_for_completion(std::chrono::seconds(5)));
    ASSERT_TRUE(http_server->wait_for_completion(std::chrono::seconds(5)));
    ASSERT_TRUE(socks_server->succeeded());
    ASSERT_TRUE(http_server->succeeded());
    ASSERT_EQ(TEST_DESTINATION_IP, socks_server->requested_address());
    ASSERT_EQ(TEST_DESTINATION_PORT, socks_server->requested_port());
    ASSERT_NE(string::npos, http_server->received_request().find("GET /local-integration HTTP/1.1"));
}

} // namespace
