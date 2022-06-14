cmake_minimum_required(VERSION 3.10)

project(credentials-fetcherd)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

file(GLOB daemon_sources "src/*.cpp")

add_executable(credentials-fetcherd ${daemon_sources})
target_link_libraries(credentials-fetcherd PUBLIC systemd)

cmake_minimum_required (VERSION 2.8)

enable_testing ()
add_subdirectory (tests)
