cmake_minimum_required(VERSION 3.10)
project (credentials-fetcher)

add_subdirectory (api)
add_subdirectory (auth)
add_subdirectory (cache)
add_subdirectory (configuration)
add_subdirectory (logging)
add_subdirectory (timer)
add_subdirectory (daemon)

# TBD: change ~/ to /usr/bin
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/daemon/build/src/credentials-fetcherd DESTINATION "~/")

project(credentials-fetcher)

cmake_minimum_required (VERSION 2.8)
