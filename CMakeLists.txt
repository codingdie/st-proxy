cmake_minimum_required(VERSION 3.11)
project(st-proxy)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpthread -latomic -Wall -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")

if(NOT EXISTS ${PROJECT_SOURCE_DIR}/src/common/main/thirdpart/httplib.h)
    file(DOWNLOAD "https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.12.6/httplib.h" ${PROJECT_SOURCE_DIR}/src/common/main/thirdpart/httplib.h)
endif()

find_package(OpenSSL 1.0.2 REQUIRED)
find_package(Boost 1.7.0 REQUIRED COMPONENTS system filesystem thread program_options log log_setup)
find_package(leveldb REQUIRED)
find_package(Protobuf REQUIRED)

# Protobuf code generation
protobuf_generate_cpp(MESSAGE_PROTO_SRCS MESSAGE_PROTO_HDRS src/core/proto/message.proto)
protobuf_generate_cpp(KV_PROTO_SRCS KV_PROTO_HDRS src/common/main/proto/kv.proto)

# Include directories
include_directories(src/core)
include_directories(src/common/main)
include_directories(src/test)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
if(APPLE)
    include_directories(src/pf/10.15.6)
endif()

# Source files
file(GLOB_RECURSE SOURCE_FILES src/core/*.cpp src/core/*.cc)
file(GLOB_RECURSE SOURCE_COMMON_FILES src/common/main/*.cpp src/common/main/*.cc)

# Main executable
add_executable(st-proxy src/server/main.cpp ${SOURCE_FILES} ${SOURCE_COMMON_FILES} ${MESSAGE_PROTO_SRCS} ${KV_PROTO_SRCS})
set(OTHER_LIBRARIES "rt" "leveldb::leveldb")
target_link_libraries(st-proxy ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES} ${Protobuf_LITE_LIBRARY})

# Install
include(GNUInstallDirs)
install(TARGETS st-proxy DESTINATION bin)
option(OPENWRT "Build for Openwrt support" OFF)

if(OPENWRT)
    install(DIRECTORY confs/openwrt/ DESTINATION etc/st/proxy)
elseif(CMAKE_HOST_APPLE)
    install(DIRECTORY confs/darwin/ DESTINATION etc/st/proxy)
elseif(CMAKE_HOST_UNIX)
    install(DIRECTORY confs/linux/ DESTINATION etc/st/proxy)
endif()

# Tests (disabled for OpenWrt)
if(NOT OPENWRT)
    file(GLOB_RECURSE SOURCE_INTEGRATION_TEST_FILES src/test/integration/*.cpp)
    file(GLOB_RECURSE SOURCE_UNIT_TEST_FILES src/test/unit/*.cpp)
    file(GLOB_RECURSE SOURCE_ST_UNIT_TEST_FILES src/common/test/*.cpp)
    option(ST_PROXY_ENABLE_EXTERNAL_TESTS "Build tests that require external network services" OFF)

    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    set(SOURCE_TEST_RUNTIME src/test/test_runtime.cpp)
    add_executable(st-unit-test ${SOURCE_TEST_RUNTIME} ${SOURCE_ST_UNIT_TEST_FILES} ${SOURCE_COMMON_FILES} ${MESSAGE_PROTO_SRCS} ${KV_PROTO_SRCS})
    add_executable(st-proxy-unit-test ${SOURCE_TEST_RUNTIME} ${SOURCE_UNIT_TEST_FILES} ${SOURCE_FILES} ${SOURCE_COMMON_FILES} ${MESSAGE_PROTO_SRCS} ${KV_PROTO_SRCS})
    add_executable(st-proxy-integration-test ${SOURCE_TEST_RUNTIME} ${SOURCE_INTEGRATION_TEST_FILES} ${SOURCE_FILES} ${SOURCE_COMMON_FILES} ${MESSAGE_PROTO_SRCS} ${KV_PROTO_SRCS})

    if(ST_PROXY_ENABLE_EXTERNAL_TESTS)
        file(GLOB_RECURSE SOURCE_EXTERNAL_TEST_FILES src/test/external/*.cpp)
        add_executable(st-proxy-external-test ${SOURCE_TEST_RUNTIME} ${SOURCE_EXTERNAL_TEST_FILES} ${SOURCE_FILES} ${SOURCE_COMMON_FILES} ${MESSAGE_PROTO_SRCS} ${KV_PROTO_SRCS})
    endif()

    target_compile_definitions(st-unit-test PRIVATE ST_PROXY_TEST_NAT_RULE="${PROJECT_SOURCE_DIR}/confs/test/nat/rule.sh")
    target_compile_definitions(st-proxy-unit-test PRIVATE ST_PROXY_TEST_NAT_RULE="${PROJECT_SOURCE_DIR}/confs/test/nat/rule.sh" ST_PROXY_HAS_CONFIG)
    target_compile_definitions(st-proxy-integration-test PRIVATE ST_PROXY_TEST_NAT_RULE="${PROJECT_SOURCE_DIR}/confs/test/nat/rule.sh" ST_PROXY_HAS_CONFIG)
    if(ST_PROXY_ENABLE_EXTERNAL_TESTS)
        target_compile_definitions(st-proxy-external-test PRIVATE ST_PROXY_TEST_NAT_RULE="${PROJECT_SOURCE_DIR}/confs/test/nat/rule.sh" ST_PROXY_HAS_CONFIG)
    endif()

    target_link_libraries(st-unit-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES} ${Protobuf_LITE_LIBRARY})
    target_link_libraries(st-proxy-unit-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES} ${Protobuf_LITE_LIBRARY})
    target_link_libraries(st-proxy-integration-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES} ${Protobuf_LITE_LIBRARY})
    if(ST_PROXY_ENABLE_EXTERNAL_TESTS)
        target_link_libraries(st-proxy-external-test gtest_main ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OTHER_LIBRARIES} ${Protobuf_LITE_LIBRARY})
    endif()

    include(GoogleTest)
    # 单测运行在不同进程中，为每例提供独立的持久化和运行时目录，以支持安全并行。
    gtest_add_tests(TARGET st-unit-test SOURCES ${SOURCE_ST_UNIT_TEST_FILES} TEST_LIST ST_UNIT_TESTS)
    gtest_add_tests(TARGET st-proxy-unit-test SOURCES ${SOURCE_UNIT_TEST_FILES} TEST_LIST PROXY_UNIT_TESTS)
    gtest_add_tests(TARGET st-proxy-integration-test SOURCES ${SOURCE_INTEGRATION_TEST_FILES} TEST_LIST INTEGRATION_TESTS)
    if(ST_PROXY_ENABLE_EXTERNAL_TESTS)
        gtest_add_tests(TARGET st-proxy-external-test SOURCES ${SOURCE_EXTERNAL_TEST_FILES} TEST_LIST EXTERNAL_TESTS)
    endif()

    function(configure_unit_tests test_target test_list)
        foreach(test_name IN LISTS ${test_list})
            string(MAKE_C_IDENTIFIER "${test_target}_${test_name}" test_id)
            set(test_root "/tmp/st-proxy-tests/${test_id}")
            set_tests_properties(${test_name} PROPERTIES
                LABELS unit
                TIMEOUT 120
                ENVIRONMENT "ST_PROXY_DB_PREFIX=${test_id};ST_KV_FOLDER=${test_root}/kv;ST_RUNTIME_DIR=${test_root};ST_AREA_IP_DIR=${test_root}/area-ips")
        endforeach()
    endfunction()

    configure_unit_tests(st-unit-test ST_UNIT_TESTS)
    configure_unit_tests(st-proxy-unit-test PROXY_UNIT_TESTS)

    # 集成测试必须等待全部单测结束；单测之间仍可由 CTest 并行调度。
    set(ALL_UNIT_TESTS ${ST_UNIT_TESTS} ${PROXY_UNIT_TESTS})
    foreach(test_name IN LISTS INTEGRATION_TESTS)
        string(MAKE_C_IDENTIFIER "st-proxy-integration-test_${test_name}" test_id)
        set(test_root "/tmp/st-proxy-tests/${test_id}")
        set_tests_properties(${test_name} PROPERTIES
            LABELS integration
            TIMEOUT 30
            RUN_SERIAL TRUE
            DEPENDS "${ALL_UNIT_TESTS}"
            ENVIRONMENT "ST_PROXY_DB_PREFIX=${test_id};ST_KV_FOLDER=${test_root}/kv;ST_RUNTIME_DIR=${test_root};ST_AREA_IP_DIR=${test_root}/area-ips")
    endforeach()

    if(ST_PROXY_ENABLE_EXTERNAL_TESTS)
        foreach(test_name IN LISTS EXTERNAL_TESTS)
            string(MAKE_C_IDENTIFIER "st-proxy-external-test_${test_name}" test_id)
            set(test_root "/tmp/st-proxy-tests/${test_id}")
            set_tests_properties(${test_name} PROPERTIES
                LABELS external
                TIMEOUT 30
                RUN_SERIAL TRUE
                DEPENDS "${ALL_UNIT_TESTS}"
                ENVIRONMENT "ST_PROXY_DB_PREFIX=${test_id};ST_KV_FOLDER=${test_root}/kv;ST_RUNTIME_DIR=${test_root};ST_AREA_IP_DIR=${test_root}/area-ips")
        endforeach()
    endif()
endif()
