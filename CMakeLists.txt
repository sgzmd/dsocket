cmake_minimum_required(VERSION 3.6)
project(dsocket)

set(CMAKE_C_STANDARD 99)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

set(SOURCE_FILES main.c dns_utils.c dns_utils.h dns_internal.h)
add_executable(dsocket ${SOURCE_FILES})
target_link_libraries(dsocket ${OPENSSL_LIBRARIES})