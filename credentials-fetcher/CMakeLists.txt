cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher)

set(CMAKE_CXX_FLAGS "-std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -pthread")

set(config)
add_subdirectory(config)
set(auth)
add_subdirectory(auth)
set(cache)
add_subdirectory(cache)
set(timer)
add_subdirectory(timer)
set(logger)
add_subdirectory(logger)
set(api)
add_subdirectory(api)
set(daemon)
add_subdirectory(daemon)

set(sources ${auth} ${daemon} ${config} ${cache} ${timer} ${logger} ${api})

add_library(cf-sources SHARED "${sources}" common)
target_include_directories(cf-sources PUBLIC common)

add_executable(credentials-fetcherd ${sources})
target_include_directories(credentials-fetcherd PUBLIC common)

target_link_libraries(credentials-fetcherd PUBLIC systemd boost_program_options ldap krb5 cf-sources)

project(credentials-fetcher)

install(FILES ${CMAKE_BINARY_DIR}/credentials-fetcherd
        DESTINATION "/usr/sbin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
install(FILES ${CMAKE_BINARY_DIR}/scripts/systemd/credentials-fetcher.service
        DESTINATION "/etc/systemd/system/")
install(FILES ${CMAKE_BINARY_DIR}/config/config.json
        DESTINATION "/etc/credentials-fetcher/")
file(TOUCH "${CMAKE_BINARY_DIR}/.ignore")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/etc/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/var/log/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/.ignore DESTINATION "/usr/share/credentials-fetcher/")
install(FILES ${CMAKE_BINARY_DIR}/libcf-sources.so
        DESTINATION "/usr/lib64/credentials-fetcher/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ)
file(WRITE "${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file"  "LD_LIBRARY_PATH=/usr/lib64/credentials-fetcher:$LD_LIBRARY_PATH")
install(FILES ${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file DESTINATION "/etc/credentials-fetcher")

cmake_minimum_required(VERSION 2.8)
