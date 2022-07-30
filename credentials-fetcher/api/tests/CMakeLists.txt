cmake_minimum_required(VERSION 3.10)

# set the project name
project(api-tests)

enable_testing()


file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/stress_test_scripts/credspec_stress_test.txt
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

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


