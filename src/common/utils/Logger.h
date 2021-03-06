//
// Created by codingdie on 2020/5/19.
//

#ifndef ST_LOGGER_H
#define ST_LOGGER_H

#include "TimeUtils.h"
#include "asio/STUtils.h"
#include <boost/property_tree/ptree.hpp>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>


static const char *const SPLIT = " ";
using namespace std;
namespace st {
    namespace utils {
        class UDPLogServer {
        public:
            string ip = "";
            uint16_t port = 0;
        };
        class LogConfig {
        public:
            uint8_t logLevel = 2;
            UDPLogServer rawLogServer;
            UDPLogServer apmLogServer;
        };
        class UDPLogger {
        public:
            static UDPLogger INSTANCE;
            UDPLogger();
            ~UDPLogger();
            void log(const string ip, const int port, const string str);

        private:
            boost::asio::io_context ctx;
            boost::asio::io_context::work *worker;
            std::thread *th;
        };
        class STDLogger {
        public:
            string tag = "";
            static STDLogger INSTANCE;
            STDLogger();
            void log(const string str, ostream *st);
        };
        class Logger {
        private:
            string levelName;
            uint32_t level = 0;
            string str;
            void appendStr(const string &info);
            void doLog(const string &time, ostream &st, const string &line);
            ostream *getSTD();
            bool enableUDPLogger();

        public:
            void static init(boost::property_tree::ptree &config);
            static thread_local uint64_t traceId;
            enum MASK { ENDL };
            static thread_local Logger DEBUG;
            static thread_local Logger WARN;
            static thread_local Logger INFO;
            static thread_local Logger ERROR;
            static thread_local boost::asio::io_context ctxThreadLocal;

            static uint32_t LEVEL;
            static string udpServerIP;
            static uint16_t udpServerPort;
            static string tag;

            explicit Logger(string levelName, uint32_t level);


            void doLog();

            Logger &operator<<(const char *log);

            Logger &operator<<(char ch);

            Logger &operator<<(const string &string);

            Logger &operator<<(char *log);

            Logger &operator<<(const unordered_set<string> &strs);

            template<typename A>
            Logger &operator<<(const A &str1) {
                if (typeid(str1) == typeid(MASK) && str1 == ENDL) {
                    doLog();
                } else {
                    this->appendStr(to_string(str1));
                }
                return *this;
            }
        };
        #define END st::utils::Logger::MASK::ENDL;
        class APMLogger {
        public:
            static string udpServerIP;
            static uint16_t udpServerPort;
            APMLogger(const string name, const string traceId);
            void step(const string step, const boost::property_tree::ptree &properties);
            void step(const string step);
            void start();
            void end();
            template<class V>
            void addDimension(const string name, const V value) {
                this->props.put<V>(name, value);
            }
            template<class V>
            void addMetric(const string name, const V value) {
                this->props.put<V>(name, value);
            }
            static void perf(const string id, const uint32_t cost, boost::property_tree::ptree &properties);


        private:
            void log(boost::property_tree::ptree &properties);
            static void doLog(boost::property_tree::ptree &properties);
            boost::property_tree::ptree props;
            uint64_t startTime;
            uint64_t lastStepTime;
        };
    }// namespace utils
}// namespace st

#endif//ST_LOGGER_H
