cmake_minimum_required(VERSION 3.10)

project(config)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/*.cpp)

set(config "${SRC_FILES}" PARENT_SCOPE)
cmake_minimum_required(VERSION 2.8)

enable_testing()
add_subdirectory(tests)
