cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher)

set(CMAKE_CXX_FLAGS "-std=c++11 -g -Wall -Werror -pthread")

find_package(Threads)

find_file(FEDORA_FOUND fedora-release PATHS /etc)
if (EXISTS ${FEDORA_FOUND})
    add_definitions(-DFEDORA_FOUND=1)
    set(protobuf_MODULE_COMPATIBLE TRUE)
    find_package(Protobuf REQUIRED)
    find_package(gRPC REQUIRED)
    set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
    set(_REFLECTION gRPC::grpc++_reflection)
    find_program(_PROTOBUF_PROTOC protoc)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
endif ()

set(config)
add_subdirectory(config)
set(api)
add_subdirectory(api)
set(auth)
add_subdirectory(auth)
set(cache)
add_subdirectory(cache)
set(timer)
add_subdirectory(timer)
set(logger)
add_subdirectory(logger)
set(daemon)
add_subdirectory(daemon)

if (EXISTS ${FEDORA_FOUND})
    set(sources ${auth} ${daemon} ${config} ${cache} ${timer} ${logger} ${api})
else ()
    set(sources ${auth} ${daemon} ${config} ${cache} ${timer} ${logger})
endif ()

add_library(cf-sources SHARED "${sources}" common)
target_include_directories(cf-sources
        PUBLIC
        common /usr/include/glib-2.0
        /usr/lib/x86_64-linux-gnu/glib-2.0/include
        /usr/lib64/glib-2.0/include)

add_executable(credentials-fetcherd ${sources})

if (EXISTS ${FEDORA_FOUND})
    cmake_policy(SET CMP0083 NEW)
    include(CheckPIESupported)
    check_pie_supported()
    if (CMAKE_C_LINK_PIE_SUPPORTED)
        set_property(TARGET credentials-fetcherd
                PROPERTY POSITION_INDEPENDENT_CODE TRUE)
    endif ()
endif ()

target_include_directories(credentials-fetcherd PUBLIC common)

if (EXISTS ${FEDORA_FOUND})
    target_link_libraries(credentials-fetcherd
            PUBLIC
            cf-gmsa-service
            ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})
endif ()

target_link_libraries(credentials-fetcherd
        PUBLIC systemd boost_program_options krb5 sqlite3 cf-sources glib-2.0)

install(FILES ${CMAKE_BINARY_DIR}/credentials-fetcherd
        DESTINATION "/usr/sbin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        )
install(FILES ${CMAKE_SOURCE_DIR}/scripts/systemd/credentials-fetcher.service
        DESTINATION "/etc/systemd/system/")
install(FILES ${CMAKE_SOURCE_DIR}/config/config.json
        DESTINATION "/etc/credentials-fetcher/")
file(TOUCH "${CMAKE_BINARY_DIR}/.ignore")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/etc/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/var/log/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/usr/share/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/libcf-sources.so
        DESTINATION "/usr/lib64/credentials-fetcher/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ)

file(WRITE "${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file" "LD_LIBRARY_PATH=/usr/lib64/credentials-fetcher:$LD_LIBRARY_PATH")
install(FILES ${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file DESTINATION "/etc/credentials-fetcher")