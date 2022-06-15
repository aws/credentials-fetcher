cmake_minimum_required(VERSION 3.10)

project(daemon)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

set(dir "${CMAKE_CURRENT_SOURCE_DIR}")

list(
  APPEND sources
  "${dir}/src/daemon.cpp"
)

set(sources "${sources}" PARENT_SCOPE)

cmake_minimum_required (VERSION 2.8)

enable_testing()
add_subdirectory (tests)
