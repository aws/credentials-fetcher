cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher)

set(sources)
add_subdirectory(api)
add_subdirectory(auth)
add_subdirectory(cache)
add_subdirectory(logging)
add_subdirectory(timer)
add_subdirectory(daemon)

set(config-dir-sources)
add_subdirectory(config)

add_library(cf-config SHARED "${config-dir-sources}" common)
target_include_directories(cf-config PUBLIC common)

add_library(cf-sources SHARED "${sources}" common)
target_include_directories(cf-sources PUBLIC common)

add_executable(credentials-fetcherd ${sources})
target_include_directories(credentials-fetcherd PUBLIC common)

target_link_libraries(credentials-fetcherd PUBLIC systemd)
target_link_libraries(credentials-fetcherd PUBLIC boost_program_options)
target_link_libraries(credentials-fetcherd PUBLIC ldap)
target_link_libraries(credentials-fetcherd PUBLIC krb5)
target_link_libraries(credentials-fetcherd PUBLIC cf-config)
target_link_libraries(credentials-fetcherd PUBLIC cf-sources)

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
install(FILES ${CMAKE_BINARY_DIR}/libcf-config.so
        DESTINATION "/usr/lib64/credentials-fetcher/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ)
install(FILES ${CMAKE_BINARY_DIR}/libcf-sources.so
        DESTINATION "/usr/lib64/credentials-fetcher/"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ)
file(WRITE "${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file"  "LD_LIBRARY_PATH=/usr/lib64/credentials-fetcher:$LD_LIBRARY_PATH")
install(FILES ${CMAKE_BINARY_DIR}/etc/credentials-fetcher/env-file DESTINATION "/etc/credentials-fetcher")

cmake_minimum_required(VERSION 2.8)
