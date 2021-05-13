
#ifndef INTERVAL_COUNTER_H
#define INTERVAL_COUNTER_H
#include "TimeUtils.h"
#include <atomic>
#include <utility>

class IntervalCounter {

public:
    uint64_t lastRecordTime;
    uint64_t startTime;
    uint64_t intervalCount;
    uint64_t totalCount;
    std::pair<uint64_t, uint64_t> interval() {
        long now = st::utils::time::now();
        uint64_t intervalTime = now - lastRecordTime;
        uint64_t count = intervalCount;
        lastRecordTime = now;
        intervalCount = 0;
        return std::make_pair<>(intervalTime, count);
    };
    std::pair<uint64_t, uint64_t> total() const {
        long now = st::utils::time::now();
        return std::make_pair<>(now - startTime, totalCount);
    };
    IntervalCounter &operator+=(const int &incr) {
        if (lastRecordTime == 0) {
            lastRecordTime = st::utils::time::now();
            startTime = lastRecordTime;
        }
        intervalCount += incr;
        totalCount += incr;
        return *this;
    }
    bool isStart() { return totalCount > 0; };
    uint64_t getLastRecordTime() { return this->lastRecordTime; };
    IntervalCounter() : lastRecordTime(0), startTime(0), intervalCount(0), totalCount(0){};
    ~IntervalCounter() {}
};

#endif
