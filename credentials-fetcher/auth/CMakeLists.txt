cmake_minimum_required(VERSION 3.10)

project(auth)
add_subdirectory (kerberos)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES kerberos/src/*.cpp)

cmake_minimum_required (VERSION 2.8)
set(sources "${SRC_FILES}" PARENT_SCOPE)
