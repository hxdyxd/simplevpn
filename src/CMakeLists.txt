cmake_minimum_required (VERSION 2.8)

set(PROJECT_NAME simplevpn)
# The version number.
set(PROJECT_VERSION "0.1.2")
project(PROJECT_NAME)

set(SIMPLEVPN_SOURSE simplevpn.c udp_alloc.c tap_client.c switch.c crypto.c cache_table.c)
set(CMAKE_EXE_LINKER_FLAGS -static)

include_directories("${PROJECT_SOURCE_DIR}/")

#link_directories()
link_libraries(pthread sodium)

add_executable(simplevpn ${SIMPLEVPN_SOURSE})

# name
target_link_libraries(simplevpn pthread sodium)

install(TARGETS simplevpn DESTINATION bin)
