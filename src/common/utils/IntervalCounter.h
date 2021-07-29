
#ifndef INTERVAL_COUNTER_H
#define INTERVAL_COUNTER_H
#include "TimeUtils.h"
#include <atomic>
#include <mutex>
#include <utility>

class IntervalCounter {

public:
    uint64_t lastIntervalTime;
    uint64_t lastRecordTime;
    uint64_t startTime;
    uint64_t intervalCount;
    uint64_t totalCount;
    std::mutex mutex;

    std::pair<uint64_t, uint64_t> interval() {
        std::lock_guard<std::mutex> guard(mutex);
        long now = st::utils::time::now();
        uint64_t intervalTime = now - lastIntervalTime;
        uint64_t count = intervalCount;
        lastIntervalTime = now;
        intervalCount = 0;
        return std::make_pair<>(intervalTime, count);
    };
    std::pair<uint64_t, uint64_t> total() const {
        long now = st::utils::time::now();
        return std::make_pair<>(now - startTime, totalCount);
    };
    IntervalCounter &operator+=(const uint64_t incr) {
        std::lock_guard<std::mutex> guard(mutex);
        lastRecordTime = st::utils::time::now();
        if (lastIntervalTime == 0) {
            lastIntervalTime = lastRecordTime;
            startTime = lastRecordTime;
        }
        intervalCount += incr;
        totalCount += incr;
        return *this;
    }
    bool isStart() { return totalCount > 0; };
    uint64_t getLastRecordTime() { return this->lastRecordTime; };
    IntervalCounter() : lastIntervalTime(0), startTime(0), intervalCount(0), totalCount(0){};
    ~IntervalCounter() {}
};

#endif
