cmake_minimum_required(VERSION 3.10)

project(auth)
add_subdirectory (kerberos)

FILE(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS kerberos/src/*.cpp kerberos/src/*.c)

set(auth "${SRC_FILES}" PARENT_SCOPE)
cmake_minimum_required (VERSION 2.8)

