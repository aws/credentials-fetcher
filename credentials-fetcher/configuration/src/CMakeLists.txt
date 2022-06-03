cmake_minimum_required(VERSION 3.10)

project(configuration)

add_executable(configuration tutorial.cxx)

target_include_directories(configuration PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
