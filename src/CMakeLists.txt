cmake_minimum_required (VERSION 2.8)

set(PROJECT_NAME simplevpn)
# The version number.
set(PROJECT_VERSION "0.1.2")
set(USE_CRYPTO OFF)

project(PROJECT_NAME)

set(SIMPLEVPN_SOURSE simplevpn.c udp_alloc.c tap_client.c switch.c cache_table.c)
set(CMAKE_EXE_LINKER_FLAGS -static)

include_directories("${PROJECT_SOURCE_DIR}/")

if(USE_CRYPTO)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_CRYPTO")
    set(SIMPLEVPN_SOURSE  "${SIMPLEVPN_SOURSE} crypto.c")
    link_libraries(pthread sodium)
    add_executable(simplevpn ${SIMPLEVPN_SOURSE})
    target_link_libraries(simplevpn pthread sodium)
else()
    link_libraries(pthread)
    add_executable(simplevpn ${SIMPLEVPN_SOURSE})
    target_link_libraries(simplevpn pthread)
endif()


install(TARGETS simplevpn DESTINATION bin)
