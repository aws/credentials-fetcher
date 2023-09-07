cmake_minimum_required(VERSION 3.10)

FILE(GLOB SRC_FILES src/*.cpp)

set(config "${SRC_FILES}" PARENT_SCOPE)

enable_testing()
