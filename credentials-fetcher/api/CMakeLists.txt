cmake_minimum_required(VERSION 3.10)

project(api)

FILE(GLOB SRC_FILES src/*.cpp)

if (EXISTS ${FEDORA_FOUND})
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

    add_library(cf-gmsa-service SHARED
            ${SRC_FILES}
            ${credentialsfetcher_proto_sources}
            ${credentialsfetcher_proto_headers}
            ${credentialsfetcher_grpc_sources}
            ${credentialsfetcher_grpc_headers}
            ${CMAKE_CURRENT_SOURCE_DIR}/../auth/kerberos/src/krb.cpp
            )

    target_include_directories(cf-gmsa-service
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../common
            /usr/include/glib-2.0
            /usr/lib/x86_64-linux-gnu/glib-2.0/include
            /usr/lib64/glib-2.0/include)

    target_compile_definitions(cf-gmsa-service PRIVATE FEDORA_FOUND)
    target_link_libraries(cf-gmsa-service
            ${_PROTOBUF_LIBPROTOBUF}
            ${_REFLECTION}
            ${_GRPC_GRPCPP}
            systemd
            glib-2.0
            boost_filesystem)

else ()
    set(api "${SRC_FILES}" PARENT_SCOPE)
endif ()


enable_testing()
add_subdirectory(tests)
