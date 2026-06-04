#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#ifdef ST_PROXY_HAS_CONFIG
#include "config.h"
#endif

#ifndef ST_PROXY_TEST_NAT_RULE
#define ST_PROXY_TEST_NAT_RULE "../confs/test/nat/rule.sh"
#endif

namespace {

std::atomic<bool> cleanup_started(false);

std::string shell_quote(const std::string &value) {
    std::string quoted = "'";
    for (char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted += ch;
        }
    }
    quoted += "'";
    return quoted;
}

bool run_network_cleanup() {
    bool expected = false;
    if (!cleanup_started.compare_exchange_strong(expected, true)) {
        return true;
    }

    const char *rule = ST_PROXY_TEST_NAT_RULE;
    std::string command =
            "if [ \"$(id -u)\" = 0 ]; then /bin/sh " + shell_quote(rule) +
            " clean; else sudo -n /bin/sh " + shell_quote(rule) +
            " clean; fi >/dev/null 2>&1";
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }

    if (pid > 0) {
        int status = 0;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) {
                break;
            }
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status) == 0;
        }
    }
    return false;
}

void unload_config_if_available() {
#ifdef ST_PROXY_HAS_CONFIG
    st::proxy::config::uniq().unload();
#endif
}

void cleanup_at_exit() {
    unload_config_if_available();
    if (!run_network_cleanup()) {
        std::cerr << "WARNING: failed to clean st-proxy test network rules" << std::endl;
    }
}

void cleanup_on_signal(int signo) {
    unload_config_if_available();
    run_network_cleanup();
    std::_Exit(128 + signo);
}

void install_cleanup_handlers() {
    std::atexit(cleanup_at_exit);

    struct sigaction action;
    action.sa_handler = cleanup_on_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGABRT, &action, nullptr);
    sigaction(SIGQUIT, &action, nullptr);
}

class NetworkCleanupEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        cleanup_started.store(false);
        if (!run_network_cleanup()) {
            std::cerr << "WARNING: failed to clean st-proxy test network rules before tests" << std::endl;
        }
        cleanup_started.store(false);
    }

    void TearDown() override {
        unload_config_if_available();
        if (!run_network_cleanup()) {
            std::cerr << "WARNING: failed to clean st-proxy test network rules after tests" << std::endl;
        }
        cleanup_started.store(false);
    }
};

struct TestRuntimeBootstrap {
    TestRuntimeBootstrap() {
        install_cleanup_handlers();
        ::testing::AddGlobalTestEnvironment(new NetworkCleanupEnvironment());
    }
};

TestRuntimeBootstrap bootstrap;

} // namespace
