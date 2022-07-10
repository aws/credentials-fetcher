cmake_minimum_required(VERSION 3.10)

project(api)

find_package(Threads REQUIRED)

FILE(GLOB SRC_FILES src/*.cpp)

if (FEDORA_FOUND)
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


	 list(APPEND SRC_FILES ${credentialsfetcher_proto_sources})
	 list(APPEND SRC_FILES ${credentialsfetcher_proto_headers})
	 list(APPEND SRC_FILES ${credentialsfetcher_grpc_sources})
	 list(APPEND SRC_FILES ${credentialsfetcher_grpc_headers})

	 add_library(cf-gmsa-service STATIC
	         ${SRC_FILES}
	         ${credentialsfetcher_proto_sources}
	         ${credentialsfetcher_proto_headers}
	         ${credentialsfetcher_grpc_sources}
	         ${credentialsfetcher_grpc_headers})

	 target_link_libraries(cf-gmsa-service
	         ${_PROTOBUF_LIBPROTOBUF}
	         ${_REFLECTION}
	         ${_GRPC_GRPCPP})

else (FEDORA_FOUND)
	   set(api "${SRC_FILES}" PARENT_SCOPE)
endif (FEDORA_FOUND)

cmake_minimum_required(VERSION 2.8)

enable_testing ()
add_subdirectory (tests)
