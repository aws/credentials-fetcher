cmake_minimum_required(VERSION 3.10)

project(daemon)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/daemon.cpp)

list(APPEND sources ${SRC_FILES})

set(sources "${sources}" PARENT_SCOPE)

cmake_minimum_required (VERSION 2.8)

enable_testing()
add_subdirectory (tests)
