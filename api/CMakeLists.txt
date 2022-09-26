cmake_minimum_required(VERSION 3.10)

project(api)

FILE(GLOB SRC_FILES src/*.cpp)

get_filename_component(credentialsfetcher_proto "../protos/credentialsfetcher.proto" ABSOLUTE)
get_filename_component(credentialsfetcher_proto_path "${credentialsfetcher_proto}" PATH)
message(${credentialsfetcher_proto})

set(credentialsfetcher_proto_sources "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.pb.cc")
set(credentialsfetcher_proto_headers "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.pb.h")
set(credentialsfetcher_grpc_sources "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.grpc.pb.cc")
set(credentialsfetcher_grpc_headers "${CMAKE_CURRENT_BINARY_DIR}/credentialsfetcher.grpc.pb.h")
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
	${CMAKE_CURRENT_SOURCE_DIR}/../metadata/src/metadata.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../metadata/tests/metadata_test.cpp)

find_path(GLIB_INCLUDE_DIR glib.h "/usr/include" "/usr/include/glib-2.0")
find_path(GLIB_CONFIG_DIR glibconfig.h "/usr/include" "/usr/lib64/glib-2.0/include")

target_include_directories(cf_gmsa_service_private
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../common
        ${GLIB_INCLUDE_DIR}
        ${GLIB_CONFIG_DIR}
	    ${CMAKE_BINARY_DIR})

target_link_libraries(cf_gmsa_service_private
        ${_PROTOBUF_LIBPROTOBUF}
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        systemd
        glib-2.0
        boost_filesystem)


enable_testing()
add_subdirectory(tests)
