cmake_minimum_required(VERSION 3.10)
project(credentials-fetcher)

set(sources)
add_subdirectory(api)
add_subdirectory(auth)
add_subdirectory(cache)
add_subdirectory(logging)
add_subdirectory(timer)
add_subdirectory(daemon)

# TBD: remove references to cpp and h files
# TBD: see if STATIC can be replaced with SHARED
add_library(cf-config STATIC config/src/config.cpp common/daemon.h)
target_include_directories(cf-config PUBLIC common)

add_executable(credentials-fetcherd ${sources})
target_include_directories(credentials-fetcherd PUBLIC common)

target_link_libraries(credentials-fetcherd PUBLIC systemd)
target_link_libraries(credentials-fetcherd PUBLIC boost_program_options)
target_link_libraries(credentials-fetcherd PUBLIC cf-config)

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

cmake_minimum_required(VERSION 2.8)
