cmake_minimum_required(VERSION 3.10)

project(config)

FILE(GLOB SRC_FILES src/*.cpp tests/*cpp)

set(config "${SRC_FILES}" PARENT_SCOPE)

enable_testing()
