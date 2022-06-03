cmake_minimum_required(VERSION 3.10)

project(api)

add_executable(api tutorial.cxx)

target_include_directories(api PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
