#note: experimental
cmake_minimum_required(VERSION 3.7)
project(udp2raw)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 11)

execute_process(COMMAND git rev-parse HEAD
                OUTPUT_VARIABLE GIT_VER
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
if (GIT_VER STREQUAL "")
  set(GIT_VER "unknown")
endif()
file(WRITE git_version.h "const char *gitversion = \"${GIT_VER}\";")

file(REMOVE makefile)

set(SOURCE_FILES
        main.cpp 
        lib/md5.cpp
        lib/pbkdf2-sha1.cpp
        lib/pbkdf2-sha256.cpp
        encrypt.cpp
        log.cpp
        network.cpp
        common.cpp
        connection.cpp
        misc.cpp
        fd_manager.cpp
        client.cpp
        server.cpp
        lib/aes_faster_c/aes.cpp
        lib/aes_faster_c/wrapper.cpp
        my_ev.cpp
)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers -O2 -g -fsanitize=address,undefined")

add_executable(udp2raw ${SOURCE_FILES})
target_link_libraries(udp2raw rt)
target_link_libraries(udp2raw pthread)
include_directories(SYSTEM "libev")
include_directories(".")
