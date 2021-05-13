
#ifndef ST_POOL_H
#define ST_POOL_H
#include <boost/pool/singleton_pool.hpp>
#include "Logger.h"
struct CHUNCK_512 {};
typedef boost::singleton_pool<CHUNCK_512, sizeof(uint8_t) * 512> CHUNCK_512_POOl;
struct CHUNCK_1024 {};
typedef boost::singleton_pool<CHUNCK_1024, sizeof(uint8_t) * 1024> CHUNCK_1024_POOl;
struct CHUNCK_2048 {};
typedef boost::singleton_pool<CHUNCK_2048, sizeof(uint8_t) * 2048> CHUNCK_2048_POOL;

static uint8_t *pmalloc(uint32_t size) {
    if (size <= 512) {
        return (uint8_t *) CHUNCK_512_POOl::malloc();
    } else if (size <= 1024) {
        return (uint8_t *) CHUNCK_1024_POOl::malloc();
    } else {
        return (uint8_t *) CHUNCK_2048_POOL::malloc();
    }
}
static void pfree(void *ptr, uint32_t size) {
    if (size <= 512) {
        CHUNCK_512_POOl::free(ptr);
    } else if (size <= 1024) {
        CHUNCK_1024_POOl::free(ptr);
    } else {
        CHUNCK_2048_POOL::free(ptr);
    }
}
#endif
