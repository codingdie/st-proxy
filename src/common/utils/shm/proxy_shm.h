//
// Created by codingdie on 7/13/22.
//

#ifndef ST_PROXY_PROXY_SHM_H
#define ST_PROXY_PROXY_SHM_H


#include "kv.h"
#include <vector>

namespace st {
    namespace proxy {

        class area_tunnel_quality {
        public:
            std::string dist;
            std::string src;
            uint64_t avg_first_package_time;
            std::string key() { return src + "_" + dist; }
        };
        class shm {
        private:
            st::shm::kv *qualities = st::shm::kv::create("PROXY-AREA-TUNNEL", 1 * 1024 * 1024);

        public:
            void update_quality(area_tunnel_quality quality);
            area_tunnel_quality get_quality(const std::string &src, const std::string &dist);
            static shm &share();
        };

    }// namespace proxy
}// namespace st

#endif//ST_PROXY_PROXY_SHM_H
