cmake_minimum_required(VERSION 3.15)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif (CCACHE_FOUND)

include(GNUInstallDirs)
include (GenerateExportHeader)
include(CMakePackageConfigHelpers)

set(PROJECT_NAME "sr25519_donna")

set(SR25519_MAJOR_VERSION 1)
set(SR25519_MINOR_VERSION 1)
set(SR25519_PATCH_VERSION 0)
set(SOVERSION "${SR25519_MAJOR_VERSION}.${SR25519_MINOR_VERSION}.${SR25519_PATCH_VERSION}")

project(sr25519_donna 
        LANGUAGES C 
        VERSION ${SOVERSION} 
        DESCRIPTION "c implementation of schnorrkel algorithm")

IF(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW) # Libraries linked via full path no longer produce linker search paths
ENDIF(COMMAND cmake_policy)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-c -O3")

OPTION(BUILD_SHARED_LIBS "Build with shared libraries." OFF)  
OPTION(TESTING "Build test programs" OFF)
OPTION(HASH_USE_SHA3_BRAINHUB "Use sha3_brainhub for hash function" OFF)

add_definitions(-DED25519_CUSTOMRANDOM)
add_definitions(-DED25519_CUSTOMHASH)
add_definitions(-DED25519_NO_INLINE_ASM)

if(SR25519_FORCE_32BIT)
  add_definitions(-DED25519_FORCE_32BIT)
endif()

if(SR25519_CUSTOMRANDOM)
  add_definitions(-DSR25519_CUSTOMRANDOM)
endif()

if(SR25519_CUSTOMHASH)
  add_definitions(-DSR25519_CUSTOMHASH)
endif()

set(SOURCE_FILES
  src/ed25519-donna/curve25519-donna-32bit.h
  src/ed25519-donna/curve25519-donna-64bit.h
  src/ed25519-donna/curve25519-donna-helpers.h
  src/ed25519-donna/curve25519-donna-sse2.h
  src/ed25519-donna/ed25519-donna-32bit-sse2.h
  src/ed25519-donna/ed25519-donna-32bit-tables.h
  src/ed25519-donna/ed25519-donna-64bit-sse2.h
  src/ed25519-donna/ed25519-donna-64bit-tables.h
  src/ed25519-donna/ed25519-donna-64bit-x86-32bit.h
  src/ed25519-donna/ed25519-donna-64bit-x86.h
  src/ed25519-donna/ed25519-donna-basepoint-table.h
  src/ed25519-donna/ed25519-donna-batchverify.h
  src/ed25519-donna/ed25519-donna-impl-base.h
  src/ed25519-donna/ed25519-donna-impl-sse2.h
  src/ed25519-donna/ed25519-donna-portable-identify.h
  src/ed25519-donna/ed25519-donna-portable.h
  src/ed25519-donna/ed25519-donna.h
  src/ed25519-donna/ed25519-hash-custom.h
  src/ed25519-donna/ed25519-hash.h
  src/ed25519-donna/ed25519-randombytes-custom.h
  src/ed25519-donna/ed25519-randombytes.h
  src/ed25519-donna/ed25519.c
  src/ed25519-donna/ed25519.h
  src/ed25519-donna/modm-donna-32bit.h
  src/ed25519-donna/modm-donna-64bit.h
  src/ed25519-donna/regression.h

  src/memzero.h
  src/memzero.c
  src/merlin.h
  src/merlin.c
  src/ristretto255.h
  src/ristretto255.c
  src/sha2.h
  src/sha2.c
  src/sha3.h 
  src/sha3.c 
  src/sha3_256.c 
  src/sha3_512.c 
  src/sr25519.c

  src/core.h
  src/core.c
  src/randombytes_sysrandom.h
  src/randombytes_sysrandom.c
  src/sr25519-randombytes-default.c

  src/sr25519-hash-custom.h
  src/sr25519-hash.h

  src/vrf.h
  src/vrf.c
  )
  
if(HASH_USE_SHA3_BRAINHUB)
  add_definitions(-DSR25519_HASH_SHA3_BRAINHUB)
endif()

set(INCLUDE_FILES
  include/sr25519.h
  include/sr25519-donna.h
  include/sr25519-randombytes.h
  include/sr25519-randombytes-custom.h
  include/sr25519-randombytes-default.h
  )

include_directories(${PROJECT_SOURCE_DIR}/src)

add_library(sr25519_donna ${LIB_TYPE} ${SOURCE_FILES} ${INCLUDE_FILES})
GENERATE_EXPORT_HEADER(sr25519_donna EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/exports/sr25519_donna_export.h)

target_include_directories(sr25519_donna
    PUBLIC 
        "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/exports>"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    
set_target_properties(sr25519_donna PROPERTIES
  VERSION ${SOVERSION}
  SOVERSION ${SOVERSION}
  INTERFACE_SR25519_MAJOR_VERSION ${SR25519_MAJOR_VERSION}
  )
set_property(
  TARGET sr25519_donna
  APPEND PROPERTY
  COMPATIBLE_INTERFACE_STRING SR25519_MAJOR_VERSION
)

install(TARGETS sr25519_donna EXPORT sr25519_donnaConfig 
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FRAMEWORK DESTINATION ${CMAKE_INSTALL_PREFIX}
  )
install(
  FILES ${INCLUDE_FILES}
  ${PROJECT_BINARY_DIR}/sr25519_donna_Export.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
  EXPORT sr25519_donnaConfig
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sr25519_donna
)
  

if (TESTING)
  enable_testing()
  
  add_executable(sr25519DonnaTests tests/test_check.c)
  target_link_libraries(sr25519DonnaTests sr25519_donna)
  
  add_test(NAME test_check COMMAND sr25519DonnaTests)
endif()
