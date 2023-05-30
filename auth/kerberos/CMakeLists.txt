cmake_minimum_required(VERSION 3.10)

project(kerberos)

file(
        COPY ${CMAKE_CURRENT_SOURCE_DIR}/src/kube2krb.py
        DESTINATION "/usr/sbin/"
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

enable_testing ()
