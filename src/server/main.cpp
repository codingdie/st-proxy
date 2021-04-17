//
// Created by codingdie on 2020/6/27.
//
#include "ProxyServer.h"
#include "utils/STUtils.h"
#include <stdlib.h>

static const vector<string> availablePaths({"../confs", "/usr/local/etc/st/proxy", "/etc/st/proxy"});
static const string pidFile = "/var/run/st-proxy.pid";

void startServer(const string &confPath) {
    st::proxy::Config::INSTANCE.load(confPath);
    ProxyServer server(st::proxy::Config::INSTANCE);
    server.start();
}

void serviceScript(const string confPath, const string op) {
    shell::exec("sh " + confPath + "/service/" + op + ".sh");
}

int main(int argc, char *argv[]) {
    bool inputConfigPath = false;
    string confPath = "";
    if (argc >= 3 && string(argv[1]) == "-c") {
        confPath = argv[2];
        inputConfigPath = true;
    } else {
        for (auto path : availablePaths) {
            if (st::utils::file::exit(path + "/config.json")) {
                confPath = path;
                break;
            }
        }
    }

    if (confPath.empty()) {
        Logger::ERROR << "the config folder not exits!" << END;
        return 0;
    }
    Logger::INFO << "the config folder is" << confPath << END;

    bool directStartServer = false;
    if (argc == 1) {
        directStartServer = true;
    } else if (argc == 3 && string(argv[1]) == "-c") {
        directStartServer = true;
    }
    if (directStartServer) {
        file::pid(pidFile);
        startServer(confPath);
    } else {
        string serviceOP = "";
        if (inputConfigPath && argc == 5 && string(argv[3]) == "-d") {
            serviceOP = string(argv[4]);
        } else if (!inputConfigPath && argc == 3 && string(argv[1]) == "-d") {
            serviceOP = string(argv[2]);
        }
        if (!serviceOP.empty()) {
            if (serviceOP == "start" || serviceOP == "stop") {
                serviceScript(confPath, serviceOP);
            } else if (serviceOP == "restart") {
                serviceScript(confPath, "stop");
                serviceScript(confPath, "start");
            } else {
                Logger::ERROR << "not support command" << END;
            }
            return 0;
        }
    }
    Logger::ERROR << "not valid command" << END;
    return 0;
}
