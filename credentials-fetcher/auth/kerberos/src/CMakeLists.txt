cmake_minimum_required(VERSION 3.10)

project(kerberos)

add_executable(kerberos tutorial.cxx)

target_include_directories(kerberos PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
