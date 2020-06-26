cmake_minimum_required(VERSION 3.11)
project(st-proxy)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpthread -Wall -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")


find_package(OpenSSL 1.0.2 REQUIRED)
find_package(Boost 1.66.0 REQUIRED COMPONENTS system filesystem thread)

include_directories(${Boost_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
message("${OPENSSL_INCLUDE_DIR}")
message("${OPENSSL_LIBRARIES}")
message("${Boost_INCLUDE_DIR}")
message("${Boost_LIBRARIES}")

include_directories(src/core)
include_directories(src/common)
IF (APPLE)
    include_directories(src/pf/10.15.6)
ENDIF ()

file(GLOB_RECURSE SOURCE_FILES src/core/*.cpp)
file(GLOB_RECURSE SOURCE_COMMON_FILES src/common/*.cpp)
message("${SOURCE_FILES}")
message("${SOURCE_COMMON_FILES}")
add_executable(st-proxy src/server/main.cpp ${SOURCE_FILES} ${SOURCE_COMMON_FILES})
add_executable(st-proxy-test src/test/main.cpp ${SOURCE_FILES} ${SOURCE_COMMON_FILES})

target_link_libraries(st-proxy ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
target_link_libraries(st-proxy-test ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})


include(GNUInstallDirs)
install(TARGETS st-proxy DESTINATION bin)
install(DIRECTORY area-ips DESTINATION etc/st)
option(OPENWRT "Build for Openwrt support" OFF)

if (OPENWRT)
    install(DIRECTORY confs/openwrt/ DESTINATION etc/st/proxy)
elseif (CMAKE_HOST_APPLE)
    install(DIRECTORY confs/darwin/ DESTINATION etc/st/proxy)
elseif (CMAKE_HOST_UNIX)
    install(DIRECTORY confs/linux/ DESTINATION etc/st/proxy)
endif ()
