cmake_minimum_required(VERSION 3.7)
project(udp2raw_tunnel)

set(CMAKE_CXX_STANDARD 11)
set_source_files_properties(lib/aes_faster_c/aes.c lib/aes_faster_c/wrapper.c lib/md5.c PROPERTIES LANGUAGE CXX )

set(SOURCE_FILES
        lib/aes_faster_c/aes.c
	lib/aes_faster_c/wrapper.c
        lib/md5.c
        common.cpp
        encrypt.cpp
        log.cpp
        main.cpp
        network.cpp
        )
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers  -static")
#set(CMAKE_LINK_LIBRARY_FLAG "-lrt")
add_executable(udp2raw_cmake ${SOURCE_FILES})
target_link_libraries(udp2raw_cmake rt)
target_link_libraries(udp2raw_cmake pthread)
