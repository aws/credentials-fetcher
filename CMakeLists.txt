cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher VERSION 1.2.0)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_FLAGS " -std=c++17 -g -Wall -Werror -pthread")

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
            "Environment=\"CF_CRED_FILE=/var/credentials-fetcher/credspec.json\"\n"
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
find_path(GLIB_CONFIG_DIR glibconfig.h "/usr/include" "/usr/lib64/glib-2.0/include" "/usr/lib/x86_64-linux-gnu/glib-2.0/include/")

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
        boost_filesystem boost_system crypto protobuf -L/usr/local/lib absl_log_internal_check_op absl_leak_check absl_die_if_null absl_log_internal_conditions absl_log_internal_message absl_examine_stack absl_log_internal_format absl_log_internal_proto absl_log_internal_nullguard absl_log_internal_log_sink_set absl_log_sink absl_log_entry absl_flags absl_flags_internal absl_flags_marshalling absl_flags_reflection absl_flags_private_handle_accessor absl_flags_commandlineflag absl_flags_commandlineflag_internal absl_flags_config absl_flags_program_name absl_log_initialize absl_log_globals absl_log_internal_globals absl_raw_hash_set absl_hash absl_city absl_low_level_hash absl_hashtablez_sampler absl_statusor absl_status absl_cord absl_cordz_info absl_cord_internal absl_cordz_functions absl_exponential_biased absl_cordz_handle absl_crc_cord_state absl_crc32c absl_crc_internal absl_crc_cpu_detect absl_bad_optional_access absl_str_format_internal absl_strerror absl_synchronization absl_graphcycles_internal absl_kernel_timeout_internal absl_stacktrace absl_symbolize absl_debugging_internal absl_demangle_internal absl_malloc_internal absl_time absl_civil_time absl_time_zone absl_bad_variant_access utf8_validity utf8_range absl_strings absl_string_view absl_strings_internal absl_base rt absl_spinlock_wait absl_int128 absl_throw_delegate absl_raw_logging_internal absl_log_severity kadm5srv_mit kdb5 gssrpc gssapi_krb5 gssrpc k5crypto com_err krb5support resolv utf8_validity ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF} absl_bad_any_cast_impl absl_bad_optional_access absl_bad_variant_access absl_base absl_city absl_civil_time absl_cord absl_cord_internal absl_cordz_functions absl_cordz_handle absl_cordz_info absl_cordz_sample_token absl_crc32c absl_crc_cord_state absl_crc_cpu_detect absl_crc_internal absl_debugging_internal absl_demangle_internal absl_die_if_null absl_examine_stack absl_exponential_biased absl_failure_signal_handler absl_flags absl_flags_commandlineflag absl_flags_commandlineflag_internal absl_flags_config absl_flags_internal absl_flags_marshalling absl_flags_parse absl_flags_private_handle_accessor absl_flags_program_name absl_flags_reflection absl_flags_usage absl_flags_usage_internal absl_graphcycles_internal absl_hash absl_hashtablez_sampler absl_int128 absl_kernel_timeout_internal absl_leak_check absl_log_entry absl_log_flags absl_log_globals absl_log_initialize absl_log_internal_check_op absl_log_internal_conditions absl_log_internal_format absl_log_internal_globals absl_log_internal_log_sink_set absl_log_internal_message absl_log_internal_nullguard absl_log_internal_proto absl_log_severity absl_log_sink absl_low_level_hash absl_malloc_internal absl_periodic_sampler absl_random_distributions absl_random_internal_distribution_test_util absl_random_internal_platform absl_random_internal_pool_urbg absl_random_internal_randen absl_random_internal_randen_hwaes absl_random_internal_randen_hwaes_impl absl_random_internal_randen_slow absl_random_internal_seed_material absl_random_seed_gen_exception absl_random_seed_sequences absl_raw_hash_set absl_raw_logging_internal absl_scoped_set_env absl_spinlock_wait absl_stacktrace absl_status absl_statusor absl_str_format_internal absl_strerror absl_string_view absl_strings absl_strings_internal absl_symbolize absl_synchronization absl_throw_delegate absl_time absl_time_zone)

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
