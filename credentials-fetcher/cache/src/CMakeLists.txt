cmake_minimum_required(VERSION 3.10)

project(cache)

add_executable(cache tutorial.cxx)

target_include_directories(cache PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
