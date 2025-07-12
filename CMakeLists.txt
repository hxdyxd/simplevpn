cmake_minimum_required(VERSION 3.2)
project(simplevpn C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" UPPERCASE_BUILD_TYPE)
if(UPPERCASE_BUILD_TYPE STREQUAL "RELEASE")
    set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
endif()

if(DEFINED CMAKE_TOOLCHAIN_FILE)
    message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}")
endif()

option(DISABLE_SODIUM "Disable libsodium dependency" ON)
option(DISABLE_WOLFSSL "Disable mbedtls dependency" OFF)

# Base files
set(BASE_SOURCES
    src/cache_table.c
    src/log.c
    src/rip.c
    src/switch.c
    src/udp_alloc.c
    src/utils.c
)

# Main files
set(MAIN_SOURCES
    src/daemon.c
    src/simplevpn.c
)

set(HEADERS
    src/app_debug.h
    src/blake2-impl.h
    src/blake2.h
    src/cache_table.h
    src/crypto.h
    src/daemon.h
    src/list.h
    src/log.h
    src/netclock.h
    src/rip.h
    src/simplevpn.h
    src/udp_alloc.h
    src/uthash.h
    src/utils.h
)

if(NOT DISABLE_SODIUM)
    list(APPEND  BASE_SOURCES
        src/crypto.c
    )
    add_definitions(-DUSE_CRYPTO)
    message(STATUS "libsodium enabled")
elseif(NOT DISABLE_WOLFSSL)
    list(APPEND  BASE_SOURCES
        src/blake2b-ref.c
        src/crypto_wolfssl.c
    )
    add_definitions(-DUSE_CRYPTO)
    message(STATUS "wolfSSL enabled")
endif()

set(PROJECT_STATIC_NAME "${PROJECT_NAME}_static")
set(PROJECT_SHARED_NAME "${PROJECT_NAME}_shared")


# STATIC
add_library(${PROJECT_STATIC_NAME} STATIC ${BASE_SOURCES} ${HEADERS})
target_include_directories(${PROJECT_STATIC_NAME} PUBLIC src)
set_target_properties(${PROJECT_STATIC_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

# SHARED
add_library(${PROJECT_SHARED_NAME} SHARED ${BASE_SOURCES} ${HEADERS})
target_include_directories(${PROJECT_SHARED_NAME} PUBLIC src)
set_target_properties(${PROJECT_SHARED_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_executable(${PROJECT_NAME} ${MAIN_SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_STATIC_NAME})
target_include_directories(${PROJECT_NAME} PRIVATE src)
add_dependencies(${PROJECT_NAME} ${PROJECT_STATIC_NAME})


if(NOT DISABLE_SODIUM)
    include(ExternalProject)

    if(CMAKE_CROSSCOMPILING)
        set(CONFIGURE_ENV 
            CC=${CMAKE_C_COMPILER} 
            CXX=${CMAKE_CXX_COMPILER}
        )
        set(CONFIGURE_OPTS
            --host=${CMAKE_SYSTEM_PROCESSOR}
        )
    else()
        set(CONFIGURE_ENV "")
        set(CONFIGURE_OPTS "")
    endif()

    set(SODIUM_INSTALL_DIR "${CMAKE_BINARY_DIR}/libsodium")
    file(MAKE_DIRECTORY "${SODIUM_INSTALL_DIR}/include")
    file(MAKE_DIRECTORY "${SODIUM_INSTALL_DIR}/lib")

    ExternalProject_Add(
        libsodium
        URL            "https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz"
        URL_HASH       SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
        PREFIX        "${SODIUM_INSTALL_DIR}"
        INSTALL_DIR   "${SODIUM_INSTALL_DIR}"
        CONFIGURE_COMMAND 
            ${CONFIGURE_ENV}
            <SOURCE_DIR>/configure
            --prefix=${SODIUM_INSTALL_DIR}
            --enable-static
            --enable-shared
            ${CONFIGURE_OPTS}
        BUILD_COMMAND   make
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 0
        BUILD_BYPRODUCTS 
            "${SODIUM_INSTALL_DIR}/lib/libsodium.a"
            "${SODIUM_INSTALL_DIR}/lib/libsodium.so"
    )

    # import libsodium
    add_library(libsodium_static STATIC IMPORTED)
    add_dependencies(libsodium_static libsodium)
    
    set_target_properties(libsodium_static PROPERTIES
        IMPORTED_LOCATION "${SODIUM_INSTALL_DIR}/lib/libsodium.a"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INSTALL_DIR}/include"
    )

    # import libsodium
    add_library(libsodium_shared SHARED IMPORTED)
    add_dependencies(libsodium_shared libsodium)
    
    set_target_properties(libsodium_shared PROPERTIES
        IMPORTED_LOCATION "${SODIUM_INSTALL_DIR}/lib/libsodium.so"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INSTALL_DIR}/include"
    )

    add_dependencies(${PROJECT_STATIC_NAME} libsodium)
    target_link_libraries(${PROJECT_STATIC_NAME} libsodium_static)
    target_include_directories(${PROJECT_STATIC_NAME} PRIVATE "${SODIUM_INSTALL_DIR}/include")

    add_dependencies(${PROJECT_SHARED_NAME} libsodium)
    target_link_libraries(${PROJECT_SHARED_NAME} libsodium_shared)
    target_include_directories(${PROJECT_SHARED_NAME} PRIVATE "${SODIUM_INSTALL_DIR}/include")

elseif(NOT DISABLE_WOLFSSL)
    include(FetchContent)

    FetchContent_Declare(
        wolfssl
        URL            "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.0-stable.tar.gz"
        URL_HASH       SHA256=f90f18c7f12913a0b351b1f4305e768697ea1380794df1f2984b9452ab0aeeaf
    )

    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(BUILD_SHARED_LIBS  OFF)

    FetchContent_MakeAvailable(wolfssl)

    add_dependencies(${PROJECT_STATIC_NAME} wolfssl)
    target_link_libraries(${PROJECT_STATIC_NAME} wolfssl)

    add_dependencies(${PROJECT_SHARED_NAME} wolfssl)
    target_link_libraries(${PROJECT_SHARED_NAME} wolfssl)
endif()

# install
install(TARGETS ${PROJECT_STATIC_NAME} DESTINATION lib)
install(TARGETS ${PROJECT_SHARED_NAME} DESTINATION lib)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
