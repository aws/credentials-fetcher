cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_FLAGS "-std=c++11 -g -Wall -Werror -pthread")

set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
find_program(_PROTOBUF_PROTOC protoc)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
file(STRINGS /etc/os-release DISTRO REGEX "^NAME=")
string(REGEX REPLACE "NAME=\"(.*)\"" "\\1" DISTRO "${DISTRO}")

set(CMAKE_VERBOSE_MAKEFILE ON)

set(config)
add_subdirectory(config)
set(api)
add_subdirectory(api)
set(renewal)
add_subdirectory(renewal)
set(daemon)
add_subdirectory(daemon)
set(metadata)
add_subdirectory(metadata)

if (NOT CF_KRB_DIR)
    set(CF_KRB_DIR "/var/credentials-fetcher/krbdir")
endif()

if (NOT CF_UNIX_DOMAIN_SOCKET_DIR)
    set(CF_UNIX_DOMAIN_SOCKET_DIR "/var/credentials-fetcher/socket")
endif()

if (NOT CF_LOGGING_DIR)
    set(CF_LOGGING_DIR "/var/credentials-fetcher/logging")
endif()

if (NOT CF_TEST_DOMAIN_NAME)
    set(CF_TEST_DOMAIN_NAME "contoso.com")
endif()

if (NOT CF_TEST_GMSA_ACCOUNT)
    set(CF_TEST_GMSA_ACCOUNT "webapp01")
endif()

configure_file(${CMAKE_SOURCE_DIR}/config/config.h.in
    ${CMAKE_BINARY_DIR}/config.h @ONLY)

if(DISTRO MATCHES "^(Amazon Linux)$")
file(WRITE scripts/systemd/credentials-fetcher.service
  "[Unit]\n"
  "Description=credentials-fetcher systemd service unit file.\n\n"
  "[Service]\n"
  "ExecStartPre=mkdir -p ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}\n"
  "ExecStartPre=chgrp ec2-user /var/credentials-fetcher ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}\n"
  "ExecStartPre=chmod 755 /var/credentials-fetcher ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}\n"
  "ExecStart=/usr/sbin/credentials-fetcherd\n"
  "ExecStartPost=chgrp ec2-user /var/credentials-fetcher/socket/credentials_fetcher.sock\n"
  "ExecStartPost=chmod 660 /var/credentials-fetcher/socket/credentials_fetcher.sock\n"
  "Environment=\"CREDENTIALS_FETCHERD_STARTED_BY_SYSTEMD=1\"\n"
  "Type=notify\n"
  "NotifyAccess=main\n"
  "WatchdogSec=5s\n"
  "Restart=on-failure\n\n"
  "[Install]\n"
  "WantedBy=multi-user.target\n"
)
else()
    file(WRITE scripts/systemd/credentials-fetcher.service
            "[Unit]\n"
            "Description=credentials-fetcher systemd service unit file.\n\n"
            "[Service]\n"
            "ExecStartPre=mkdir -p ${CF_KRB_DIR} ${CF_UNIX_DOMAIN_SOCKET_DIR} ${CF_LOGGING_DIR}\n"
            "ExecStart=/usr/sbin/credentials-fetcherd\n"
            "Environment=\"CREDENTIALS_FETCHERD_STARTED_BY_SYSTEMD=1\"\n"
            "Type=notify\n"
            "NotifyAccess=main\n"
            "WatchdogSec=5s\n"
            "Restart=on-failure\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
            )
endif()

set(sources ${daemon} ${config} ${renewal})

add_executable(credentials-fetcherd ${sources})

cmake_policy(SET CMP0083 NEW)
include(CheckPIESupported)
check_pie_supported()
if (CMAKE_C_LINK_PIE_SUPPORTED)
   set_property(TARGET credentials-fetcherd
                PROPERTY POSITION_INDEPENDENT_CODE TRUE)
   set_property(TARGET cf_gmsa_service_private
                PROPERTY POSITION_INDEPENDENT_CODE TRUE)
endif ()

find_path(GLIB_INCLUDE_DIR glib.h "/usr/include" "/usr/include/glib-2.0")
find_path(GLIB_CONFIG_DIR glibconfig.h "/usr/include" "/usr/lib64/glib-2.0/include")

target_include_directories(credentials-fetcherd
        PUBLIC
        common
        ${GLIB_INCLUDE_DIR}
        ${GLIB_CONFIG_DIR}
        ${CMAKE_CURRENT_BINARY_DIR})

find_program(DOTNET dotnet ~/.dotnet /usr/bin)
if (NOT DOTNET)
    message(FATAL_ERROR ".NET compiler is not found")
endif()

add_custom_command(
    TARGET credentials-fetcherd
    PRE_LINK
    COMMAND bash -c  "CURR_DIR=$PWD && echo $CURR_DIR && cd ${CMAKE_CURRENT_SOURCE_DIR}/auth/kerberos/src/utf16_decode && ./build-using-csc.sh Program.cs && cp Program.exe $CURR_DIR/credentials_fetcher_utf16_private.exe && cp Program.runtimeconfig.json $CURR_DIR/credentials_fetcher_utf16_private.runtimeconfig.json"
    VERBATIM)

target_include_directories(credentials-fetcherd PUBLIC common)

target_link_libraries(credentials-fetcherd
        PUBLIC systemd boost_program_options krb5 glib-2.0 cf_gmsa_service_private
        boost_filesystem boost_system crypto
        kadm5srv_mit kdb5 gssrpc gssapi_krb5 gssrpc k5crypto
        com_err krb5support resolv)

target_link_libraries(credentials-fetcherd
            PUBLIC
            ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

install(FILES ${CMAKE_BINARY_DIR}/credentials-fetcherd
        DESTINATION "/usr/sbin/"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(FILES ${CMAKE_SOURCE_DIR}/scripts/systemd/credentials-fetcher.service
        DESTINATION "/usr/lib/systemd/system/")
install(FILES ${CMAKE_BINARY_DIR}/credentials_fetcher_utf16_private.exe
        DESTINATION "/usr/sbin/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
install(FILES ${CMAKE_BINARY_DIR}/credentials_fetcher_utf16_private.runtimeconfig.json
        DESTINATION "/usr/sbin/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)

enable_testing()

add_test(NAME check_help COMMAND ${CMAKE_BINARY_DIR}/credentials-fetcherd "--help")
add_test(NAME run_self_test COMMAND ${CMAKE_BINARY_DIR}/credentials-fetcherd "--self_test")
set_tests_properties(check_help PROPERTIES WILL_FAIL TRUE)
set_tests_properties(run_self_test PROPERTIES WILL_FAIL FALSE)
