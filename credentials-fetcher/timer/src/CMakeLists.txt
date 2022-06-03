cmake_minimum_required(VERSION 3.10)

project(timer)

add_executable(timer tutorial.cxx)

target_include_directories(timer PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
