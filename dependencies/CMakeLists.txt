cmake_minimum_required(VERSION 3.10)

project(build_binaries)

add_custom_target(build_krb5)
add_custom_command(TARGET build_krb5
   COMMAND rm -rf ${CMAKE_BINARY_DIR}/krb5-krb5-1.21.2-final
   COMMAND tar zxvf ${CMAKE_SOURCE_DIR}/krb5-1.21.2-final.tar.gz
   WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
   COMMAND cd krb5-krb5-1.21.2-final/src && autoreconf && mkdir -p ${PROJECT_BINARY_DIR}/binaries/krb5 && ./configure prefix=${PROJECT_BINARY_DIR}/binaries/krb5 && make -j && make install
   DEPENDS ${CMAKE_SOURCE_DIR}/dependencies/krb5-1.21.2-final.tar.gz
   COMMENT "Compiling krb5-1.21.2-final.tar.gz"
   VERBATIM)

add_custom_target(build_grpc)
add_custom_command(TARGET build_grpc 
   COMMAND rm -rf ${CMAKE_BINARY_DIR}/grpc
   COMMAND tar zxvf ${CMAKE_SOURCE_DIR}/grpc-v1.57.0.tar.gz
   WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
   COMMAND mkdir -p ${PROJECT_BINARY_DIR}/binaries/grpc/bin ${PROJECT_BINARY_DIR}/binaries/grpc/lib
   COMMAND cd grpc && mkdir -p build/grpc/bin build/grpc/lib && cd build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DCMAKE_CXX_STANDARD=17 -DCMAKE_INSTALL_PREFIX=${PROJECT_BINARY_DIR}/binaries/grpc -DgRPC_INSTALL_BINDIR=${PROJECT_BINARY_DIR}/binaries/grpc/bin -DgRPC_INSTALL_LIBDIR=${PROJECT_BINARY_DIR}/binaries/grpc/lib ../ && make -j && make install
   DEPENDS ${CMAKE_SOURCE_DIR}/dependencies/grpc-v1.57.0.tar.gz
   COMMENT "Compiling grpc-1.57.0.tar.gz"
   VERBATIM)
