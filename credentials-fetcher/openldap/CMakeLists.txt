cmake_minimum_required(VERSION 3.10)

project(openldap)

add_custom_target(get_and_configure_openldap ALL
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/get_openldap.sh" "${CMAKE_CURRENT_BINARY_DIR}/openldap")

add_custom_target(build_openldap ALL
                   DEPENDS get_and_configure_openldap
                   COMMAND make
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/openldap/)
