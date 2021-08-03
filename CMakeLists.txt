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
include_directories(src/test)
IF (APPLE)
    include_directories(src/pf/10.15.6)
ENDIF ()

file(GLOB_RECURSE SOURCE_FILES src/core/*.cpp)
file(GLOB_RECURSE SOURCE_COMMON_FILES src/common/*.cpp)
file(GLOB_RECURSE SOURCE_INTEGRATION_TEST_FILES src/test/integration/*.cpp)
file(GLOB_RECURSE SOURCE_UNIT_TEST_FILES src/test/unit/*.cpp)
message("${SOURCE_FILES}")
message("${SOURCE_COMMON_FILES}")
add_executable(st-proxy src/server/main.cpp ${SOURCE_FILES} ${SOURCE_COMMON_FILES})
set(OTHER_LIBRARIES "rt")
target_link_libraries(st-proxy ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES})


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

if(NOT OPENWRT)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    add_executable(st-proxy-unit-test ${SOURCE_UNIT_TEST_FILES} ${SOURCE_FILES} ${SOURCE_COMMON_FILES})
    add_executable(st-proxy-integration-test ${SOURCE_INTEGRATION_TEST_FILES} ${SOURCE_FILES} ${SOURCE_COMMON_FILES})
    target_link_libraries(st-proxy-unit-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES})
    target_link_libraries(st-proxy-integration-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES})
    include(GoogleTest)
    gtest_discover_tests(st-proxy-unit-test)
    gtest_discover_tests(st-proxy-integration-test)
endif()
