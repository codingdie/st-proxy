//
// Created by codingdie on 7/13/22.
//

#include "proxy_shm.h"

namespace st {
    namespace proxy {
        shm &shm::share() {
            static shm in;
            return in;
        }
        void shm::update_quality(area_tunnel_quality quality) {
            qualities->put(quality.key(), quality.avg_first_package_time);
        }
        area_tunnel_quality shm::get_quality(const std::string &src, const std::string &dist) {
            area_tunnel_quality quality;
            quality.src = src;
            quality.dist = dist;
            quality.avg_first_package_time = 0;
            auto strValue = qualities->get(quality.key());
            if (!strValue.empty()) {
                quality.avg_first_package_time = std::stoul(strValue);
            }
            return quality;
        }
    }// namespace proxy
}// namespace st