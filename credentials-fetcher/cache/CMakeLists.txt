cmake_minimum_required(VERSION 3.10)

project(cache)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/*.cpp)

set(cache "${SRC_FILES}" PARENT_SCOPE)

enable_testing ()
add_subdirectory (tests)
