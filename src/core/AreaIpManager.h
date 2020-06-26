//
// Created by codingdie on 2020/10/8.
//

#ifndef ST_AREAIP_MANAGER_H
#define ST_AREAIP_MANAGER_H

#include <iostream>
#include <mutex>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;


class AreaIpManager {
private:
    static AreaIpManager INSTANCE;
    unordered_map<string, vector<pair<uint32_t, uint32_t>> *> caches;
    static bool isAreaIPBase(const string &areaCode, const uint32_t &ip);

public:
    static bool isAreaIP(const string &areaCode, const uint32_t &ip);
};


#endif//ST_AREAIP_MANAGER_H
