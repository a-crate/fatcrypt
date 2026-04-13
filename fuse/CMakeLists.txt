cmake_minimum_required(VERSION 3.12)
project(fatcrypt
    VERSION 0.2
    DESCRIPTION "a partially encrypted filesystem with the same on-disk format as FAT"
    HOMEPAGE_URL "https://github.com/a-crate/fatcrypt"
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

find_package(PkgConfig)
pkg_check_modules(FUSE fuse3)
if(NOT FUSE_FOUND)
	pkg_check_modules(FUSE REQUIRED fuse)
endif()
string(REGEX REPLACE "\\..*" "" FUSE_VERSION ${FUSE_VERSION})

pkg_check_modules(JSON_C REQUIRED json-c)

# Add vendored wolfSSL
set(WOLFSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl)
include_directories(${WOLFSSL_DIR})
add_definitions(-DWOLFSSL_USER_SETTINGS)

# Build minimal wolfSSL crypto library
set(WOLFSSL_SOURCES
	${WOLFSSL_DIR}/wolfcrypt/src/hmac.c
	${WOLFSSL_DIR}/wolfcrypt/src/sha256.c
	${WOLFSSL_DIR}/wolfcrypt/src/hash.c
	${WOLFSSL_DIR}/wolfcrypt/src/kdf.c
	${WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
	${WOLFSSL_DIR}/wolfcrypt/src/random.c
	${WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
	${WOLFSSL_DIR}/wolfcrypt/src/memory.c
	${WOLFSSL_DIR}/wolfcrypt/src/error.c
	${WOLFSSL_DIR}/wolfcrypt/src/logging.c
	${WOLFSSL_DIR}/wolfcrypt/src/chacha20_poly1305.c
	${WOLFSSL_DIR}/wolfcrypt/src/poly1305.c
	${WOLFSSL_DIR}/wolfcrypt/src/chacha.c
)

set(CMAKE_REQUIRED_DEFINITIONS -D_FILE_OFFSET_BITS=64)

configure_file(config.h.in config.h @ONLY)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra -Werror")

add_definitions(-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 ${FUSE_CFLAGS} -DFUSE=${FUSE_VERSION})

add_executable(fatcrypt fusefatfs.c fftable.c diskio.c ff.c ffunicode.c fatcrypt.c ${WOLFSSL_SOURCES})
target_link_libraries(fatcrypt ${FUSE_LIBRARIES} ${JSON_C_LIBRARIES})
target_include_directories(fatcrypt PRIVATE ${JSON_C_INCLUDE_DIRS})
install(TARGETS fatcrypt
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

