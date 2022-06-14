cmake_minimum_required(VERSION 3.10)
project (credentials-fetcher)

add_subdirectory (api)
add_subdirectory (auth)
add_subdirectory (cache)
add_subdirectory (configuration)
add_subdirectory (logging)
add_subdirectory (timer)
add_subdirectory (daemon)

project(credentials-fetcher)

install(FILES ${CMAKE_BINARY_DIR}/daemon/credentials-fetcherd
        DESTINATION "/usr/sbin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
install(FILES ${CMAKE_BINARY_DIR}/scripts/systemd/credentials-fetcher.service
        DESTINATION "/etc/systemd/system/")

cmake_minimum_required (VERSION 2.8)
