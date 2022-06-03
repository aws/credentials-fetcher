cmake_minimum_required(VERSION 3.10)

project(credentials-fetcherd)

add_executable(credentials-fetcherd tutorial.cxx)

target_include_directories(credentials-fetcherd PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
