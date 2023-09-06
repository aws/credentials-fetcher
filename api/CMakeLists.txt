cmake_minimum_required(VERSION 3.10)

project(api)

FILE(GLOB SRC_FILES src/*.cpp tests/gmsa_service_test.cpp)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(cf_gmsa_service_private OBJECT
    ${SRC_FILES})

find_path(GLIB_INCLUDE_DIR glib.h "/usr/include" "/usr/include/glib-2.0")
find_path(GLIB_CONFIG_DIR glibconfig.h "/usr/include" "/usr/lib64/glib-2.0/include")

file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/src/credentials_fetcher_krbsecret_to_kubesecret.py
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

target_compile_options(cf_gmsa_service_private PUBLIC -DCREDENTIALS_FETCHERD_NO_GRPC)

target_include_directories(cf_gmsa_service_private
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../common
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kinit_client
        ${GLIB_INCLUDE_DIR}
        ${GLIB_CONFIG_DIR}
        ${CMAKE_BINARY_DIR})

target_link_libraries(cf_gmsa_service_private
        systemd
        glib-2.0
        boost_system boost_filesystem
        krb5 kadm5srv_mit kdb5 gssrpc gssapi_krb5 gssrpc k5crypto crypto ssl
        com_err krb5support resolv jsoncpp)

enable_testing()
add_subdirectory(tests)
