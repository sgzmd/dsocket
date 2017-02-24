cmake_minimum_required(VERSION 3.6)
project(dsocket)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c dns_utils.c dns_utils.h dns_internal.h)
add_executable(dsocket ${SOURCE_FILES})