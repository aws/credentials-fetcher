cmake_minimum_required(VERSION 3.10)

project(logger)

FILE(GLOB SRC_FILES src/*.cpp)
set(logger "${SRC_FILES}" PARENT_SCOPE)

enable_testing ()
add_subdirectory (tests)
