cmake_minimum_required(VERSION 3.10)

project(metadata)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/*.cpp) 

set(metadata "${SRC_FILES}" PARENT_SCOPE)

enable_testing ()
