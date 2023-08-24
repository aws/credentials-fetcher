cmake_minimum_required(VERSION 3.10)

project(daemon)

FILE(GLOB SRC_FILES src/*.cpp)

set(daemon "${SRC_FILES}" PARENT_SCOPE)

file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/credentials_fetcher.conf
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../
        FILE_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
)

enable_testing()
