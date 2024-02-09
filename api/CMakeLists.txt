cmake_minimum_required(VERSION 3.10)

project(api)

FILE(GLOB SRC_FILES src/*.cpp)

get_filename_component(credentialsfetcher_proto "../protos/credentialsfetcher.proto" ABSOLUTE)
get_filename_component(credentialsfetcher_proto_path "${credentialsfetcher_proto}" PATH)
message(${credentialsfetcher_proto})
set(AWSSDK_INSTALL_LIBDIR /usr/lib64)

set(SERVICE_COMPONENTS s3 secretsmanager)
set(credentialsfetcher_proto_sources "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.pb.cc")
set(credentialsfetcher_proto_headers "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.pb.h")
set(credentialsfetcher_grpc_sources "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.grpc.pb.cc")
set(credentialsfetcher_grpc_headers "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.grpc.pb.h")

if(${DISTRO_ID} MATCHES "amzn")
    find_package(AWSSDK REQUIRED COMPONENTS ${SERVICE_COMPONENTS})
endif()

add_custom_command(
        OUTPUT "${credentialsfetcher_proto_sources}" "${credentialsfetcher_proto_headers}" "${credentialsfetcher_grpc_sources}" "${credentialsfetcher_grpc_headers}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${credentialsfetcher_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${credentialsfetcher_proto}"
        DEPENDS "${credentialsfetcher_proto}")

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

list(APPEND SRC_FILES ${credentialsfetcher_proto_sources})
list(APPEND SRC_FILES ${credentialsfetcher_proto_headers})
list(APPEND SRC_FILES ${credentialsfetcher_grpc_sources})
list(APPEND SRC_FILES ${credentialsfetcher_grpc_headers})

add_library(cf_gmsa_service_private OBJECT
    ${SRC_FILES}
    ${credentialsfetcher_proto_sources}
    ${credentialsfetcher_proto_headers}
    ${credentialsfetcher_grpc_sources}
    ${credentialsfetcher_grpc_headers}
    ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kerberos/src/krb.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kinit_client/kinit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kinit_client/kinit_kdb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../metadata/src/metadata.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../metadata/tests/metadata_test.cpp)

find_path(GLIB_INCLUDE_DIR glib.h "/usr/include" "/usr/include/glib-2.0")
find_path(GLIB_CONFIG_DIR glibconfig.h "/usr/include" "/usr/lib64/glib-2.0/include" "/usr/lib/x86_64-linux-gnu/glib-2.0/include")

target_include_directories(cf_gmsa_service_private
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../common
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kinit_client
        ${GLIB_INCLUDE_DIR}
        ${GLIB_CONFIG_DIR}
        ${CMAKE_BINARY_DIR})

cmake_host_system_information(RESULT PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
cmake_host_system_information(RESULT DISTRO QUERY DISTRIB_INFO)

if(${DISTRO_ID} MATCHES "ubuntu")
   message(STATUS "Linux distro detected as ubuntu")
   target_link_libraries(cf_gmsa_service_private
        -L/usr/local/lib
grpc++_reflection grpc++ protobuf grpc re2 upb_json_lib upb_textformat_lib upb_collections_lib upb utf8_range_lib z absl_statusor cares gpr absl_status absl_strerror absl_flags absl_flags_internal absl_flags_reflection absl_raw_hash_set absl_hash absl_city absl_bad_variant_access absl_low_level_hash absl_hashtablez_sampler absl_flags_config absl_flags_program_name absl_flags_private_handle_accessor absl_flags_commandlineflag absl_flags_commandlineflag_internal absl_flags_marshalling absl_random_distributions absl_random_seed_sequences absl_random_internal_pool_urbg absl_random_internal_randen absl_random_internal_randen_hwaes absl_random_internal_randen_hwaes_impl absl_random_internal_randen_slow absl_random_internal_platform absl_random_internal_seed_material absl_random_seed_gen_exception absl_cord absl_bad_optional_access absl_cordz_info absl_cord_internal absl_cordz_functions absl_exponential_biased absl_cordz_handle absl_crc_cord_state absl_crc32c absl_crc_internal absl_crc_cpu_detect absl_str_format_internal absl_synchronization absl_stacktrace absl_symbolize absl_debugging_internal absl_demangle_internal absl_graphcycles_internal absl_kernel_timeout_internal absl_malloc_internal absl_time absl_strings absl_int128 absl_string_view absl_throw_delegate absl_strings_internal absl_base absl_spinlock_wait -lrt absl_raw_logging_internal absl_log_severity absl_civil_time absl_time_zone ssl crypto address_sorting
        systemd
        glib-2.0
        jsoncpp
        krb5 kadm5srv_mit kdb5 gssapi_krb5 gssrpc
	kdb5 gssrpc k5crypto com_err krb5support resolv utf8_validity
	absl_log_internal_check_op absl_leak_check absl_die_if_null absl_log_internal_conditions absl_log_internal_message absl_examine_stack absl_log_internal_format absl_log_internal_proto absl_log_internal_nullguard absl_log_internal_log_sink_set absl_log_sink absl_log_entry absl_flags absl_flags_internal absl_flags_marshalling absl_flags_reflection absl_flags_private_handle_accessor absl_flags_commandlineflag absl_flags_commandlineflag_internal absl_flags_config absl_flags_program_name absl_log_initialize absl_log_globals absl_log_internal_globals absl_raw_hash_set absl_hash absl_city absl_low_level_hash absl_hashtablez_sampler absl_statusor absl_status absl_cord absl_cordz_info absl_cord_internal absl_cordz_functions absl_exponential_biased absl_cordz_handle absl_crc_cord_state absl_crc32c absl_crc_internal absl_crc_cpu_detect absl_bad_optional_access absl_str_format_internal absl_strerror absl_synchronization absl_graphcycles_internal absl_kernel_timeout_internal absl_stacktrace absl_symbolize absl_debugging_internal absl_demangle_internal absl_malloc_internal absl_time absl_civil_time absl_time_zone absl_bad_variant_access utf8_validity utf8_range absl_strings absl_string_view absl_strings_internal absl_base rt absl_spinlock_wait absl_int128 absl_throw_delegate absl_raw_logging_internal absl_log_severity)
else()
   target_link_libraries(cf_gmsa_service_private
        ${_PROTOBUF_LIBPROTOBUF}
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        systemd
        glib-2.0
        jsoncpp
        krb5 kadm5srv_mit kdb5 gssrpc gssapi_krb5 gssrpc k5crypto
        com_err krb5support resolv ${AWSSDK_LINK_LIBRARIES})
endif()

enable_testing()
add_subdirectory(tests)
