cmake_minimum_required(VERSION 3.10)

project(renewal)

FILE(GLOB SRC_FILES src/*.cpp tests/*.cpp)

set(renewal "${SRC_FILES}" PARENT_SCOPE)

enable_testing ()
