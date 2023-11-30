cmake_minimum_required(VERSION 3.10)

project(sample_credspec)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

FILE(GLOB SRC_FILES src/*.cpp tests/*.cpp)
set(sample_credspec "${SRC_FILES}" PARENT_SCOPE)

# test sample for unit tests
file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/sample_credspec.json
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

enable_testing ()
