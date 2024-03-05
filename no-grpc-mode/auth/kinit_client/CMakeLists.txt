cmake_minimum_required(VERSION 3.10)

project(kinit_client)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES *.c)

set(kinit_client "${SRC_FILES}" PARENT_SCOPE)
