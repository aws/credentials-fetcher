cmake_minimum_required(VERSION 3.10)

project(daemon)

FILE(GLOB SRC_FILES src/*.cpp)

set(daemon "${SRC_FILES}" PARENT_SCOPE)

cmake_minimum_required (VERSION 2.8)

enable_testing()
add_subdirectory (tests)
