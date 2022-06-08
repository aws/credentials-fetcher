cmake_minimum_required(VERSION 3.10)

project(credentials-fetcherd)

file(GLOB daemon_sources "src/*.cpp")
file(GLOB daemon_sources "src/*.cxx")

add_executable(credentials-fetcherd ${daemon_sources})

cmake_minimum_required (VERSION 2.8)

enable_testing ()
add_subdirectory (tests)
