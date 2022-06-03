cmake_minimum_required(VERSION 3.10)

project(logging)

add_executable(logging tutorial.cxx)

target_include_directories(logging PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
