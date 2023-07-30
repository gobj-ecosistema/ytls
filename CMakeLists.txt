##############################################
#   CMake
##############################################
cmake_minimum_required(VERSION 3.0)
project(ytls C)
include(CheckIncludeFiles)
include(CheckSymbolExists)

set(CMAKE_INSTALL_PREFIX /yuneta/development/output)

set(INC_DEST_DIR ${CMAKE_INSTALL_PREFIX}/include)
set(LIB_DEST_DIR ${CMAKE_INSTALL_PREFIX}/lib)

set(CMAKE_C_STANDARD 99)

if(LINUX OR UNIX OR CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
ELSE()
  add_definitions(-DNOT_INCLUDE_LIBUNWIND=1)
ENDIF()

if(WIN32)
  add_definitions(-DNOT_INCLUDE_LIBUNWIND)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
  add_definitions(-DDEBUG)
  option(SHOWNOTES "Show preprocessor notes" OFF)

  if(CMAKE_COMPILER_IS_GNUCC)
    # GCC specific debug options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -ggdb3 -gdwarf-2")
    set(AVOID_VERSION -avoid-version)
  endif(CMAKE_COMPILER_IS_GNUCC)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64)

IF(WIN32)
  include_directories(c:/yuneta/development/output/include)
  include_directories(c:/yuneta/development/output/include/regex)
  include_directories(c:/yuneta/development/output/OpenSSL-Win64/include)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
ELSEIF(UNIX)
  include_directories(/yuneta/development/output/include)
ENDIF()

##############################################
#   Source
##############################################

set (SRCS
    src/ytls.c
    src/tls/openssl.c
)


set (HDRS
    src/ytls.h
)


##############################################
#   Lib
##############################################
add_library(ytls ${SRCS} ${HDRS})

##############################################
#   System install
##############################################
install(FILES ${HDRS} DESTINATION ${INC_DEST_DIR})

install(
    TARGETS ytls
    PERMISSIONS
    OWNER_READ OWNER_WRITE
    GROUP_READ GROUP_WRITE
    WORLD_READ
    DESTINATION ${LIB_DEST_DIR}
)

##############################################
#   sub-projects
##############################################
