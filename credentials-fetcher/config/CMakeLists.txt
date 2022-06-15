cmake_minimum_required(VERSION 3.10)

project(config)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

cmake_minimum_required(VERSION 2.8)

enable_testing()
add_subdirectory(tests)
