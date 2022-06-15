cmake_minimum_required(VERSION 3.10)

project(config)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/*.cpp)

cmake_minimum_required(VERSION 2.8)

set(config-dir-sources "${SRC_FILES}" PARENT_SCOPE)

enable_testing()
add_subdirectory(tests)
