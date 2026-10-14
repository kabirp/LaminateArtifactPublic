cmake_minimum_required(VERSION 3.20)
project(LaminateImpl VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build LaminateImpl tests" ON)
option(BUILD_BENCHMARKS "Build LaminateImpl benchmarks" OFF)
option(LAMINATE_WITH_SEAL "Build the Microsoft SEAL BGV backend" OFF)
option(
    LAMINATE_EXTENDED_TESTS
    "Build additional component and edge-case tests"
    OFF)
include(cmake/SealDependency.cmake)
laminate_processor_is_x86_64(
    LAMINATE_TARGET_IS_X86_64 "${CMAKE_SYSTEM_PROCESSOR}")
option(
    LAMINATE_REQUIRE_SEAL_HEXL
    "Require an Intel-HEXL-enabled SEAL package (default on x86-64)"
    "${LAMINATE_TARGET_IS_X86_64}")

set(LAMINATE_SEAL_DIR
    ""
    CACHE PATH "Directory containing SEALConfig.cmake")
set(LAMINATE_SEAL_ACCELERATION "not-built")
set(LAMINATE_SEAL_VERSION "not-built")
set(LAMINATE_SEAL_HEXL_ENABLED OFF)
if(LAMINATE_WITH_SEAL)
    laminate_find_seal(
        LAMINATE_SEAL_VERSION
        LAMINATE_SEAL_ACCELERATION
        LAMINATE_SEAL_HEXL_ENABLED)
    if(LAMINATE_SEAL_ACCELERATION STREQUAL
            "intel-hexl-runtime-dispatch" AND
       NOT LAMINATE_SEAL_HEXL_ENABLED)
        message(FATAL_ERROR
            "SEAL reports Intel HEXL acceleration, but its feature flag was "
            "not exported to Laminate's native-Fq build.")
    endif()
endif()

set(LAMINATE_SHA256_ACCELERATION "portable")
if(APPLE)
    set(LAMINATE_SHA256_ACCELERATION "commoncrypto")
else()
    find_package(OpenSSL QUIET COMPONENTS Crypto)
    if(TARGET OpenSSL::Crypto)
        set(LAMINATE_SHA256_ACCELERATION "openssl")
    endif()
endif()
message(STATUS
    "Laminate SHA-256 provider: ${LAMINATE_SHA256_ACCELERATION}")

add_subdirectory(src)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benches)
endif()
