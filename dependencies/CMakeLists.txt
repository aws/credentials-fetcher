cmake_minimum_required(VERSION 3.10)

project(build_binaries)

add_custom_target(build_krb5)
add_custom_command(TARGET build_krb5
   WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
   COMMAND rm -rf ${CMAKE_BINARY_DIR}/krb5
   COMMAND git clone https://github.com/krb5/krb5.git -b krb5-1.21.2-final
   COMMAND cd krb5/src && autoreconf && ./configure && make -j && sudo make install
   COMMENT "Compiling krb5-1.21.2-final"
   VERBATIM)

add_custom_target(build_grpc)
add_custom_command(TARGET build_grpc 
   WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
   COMMAND rm -rf ${CMAKE_BINARY_DIR}/grpc
   COMMAND git clone --recurse-submodules -b v1.58.0 https://github.com/grpc/grpc
   COMMAND cd grpc && mkdir -p build && cd build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DCMAKE_CXX_STANDARD=17 ../ && make -j && sudo make install
   COMMENT "Compiling grpc-v1.58"
   VERBATIM)
