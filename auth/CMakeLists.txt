cmake_minimum_required(VERSION 3.10)

project(auth)
add_subdirectory (kerberos)

FILE(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS kerberos/src/*.cpp
        kerberos/src/*.c kinit_client/*.c)

file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/kerberos/src
        /credentials_fetcher_krbsecret_to_kubesecret.py
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

set(auth "${SRC_FILES}" PARENT_SCOPE)

