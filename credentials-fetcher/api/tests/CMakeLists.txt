cmake_minimum_required(VERSION 3.10)

# set the project name
project(api-tests)

enable_testing()

if (EXISTS ${FEDORA_FOUND})
    add_executable(gmsa_test_client "gmsa_test_client.cpp")
    target_link_libraries(gmsa_test_client
            cf-gmsa-service
            ${_PROTOBUF_LIBPROTOBUF}
            ${_REFLECTION}
            ${_GRPC_GRPCPP})

    cmake_policy(SET CMP0083 NEW)
    include(CheckPIESupported)
    check_pie_supported()
    if (CMAKE_C_LINK_PIE_SUPPORTED)
        set_property(TARGET gmsa_test_client
                PROPERTY POSITION_INDEPENDENT_CODE TRUE)
    endif ()

endif ()

