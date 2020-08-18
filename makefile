cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
cc_mips24kc_be=/toolchains/lede-sdk-17.01.2-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-g++
cc_mips24kc_le=/toolchains/lede-sdk-17.01.2-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.16/bin/mipsel-openwrt-linux-musl-g++
cc_arm= /toolchains/lede-sdk-17.01.2-bcm53xx_gcc-5.4.0_musl-1.1.16_eabi.Linux-x86_64/staging_dir/toolchain-arm_cortex-a9_gcc-5.4.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-c++
cc_mingw_cross=i686-w64-mingw32-g++-posix
cc_mac_cross=o64-clang++ -stdlib=libc++
cc_x86=/toolchains/lede-sdk-17.01.2-x86-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-c++
cc_amd64=/toolchains/lede-sdk-17.01.2-x86-64_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-5.4.0_musl-1.1.16/bin/x86_64-openwrt-linux-c++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 


FLAGS= -std=c++11   -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT}

COMMON=main.cpp lib/md5.cpp lib/pbkdf2-sha1.cpp lib/pbkdf2-sha256.cpp encrypt.cpp log.cpp network.cpp common.cpp  connection.cpp misc.cpp fd_manager.cpp client.cpp server.cpp -lpthread

SOURCES0= $(COMMON) lib/aes_faster_c/aes.cpp lib/aes_faster_c/wrapper.cpp
SOURCES= ${SOURCES0} my_ev.cpp -isystem libev
SOURCES_AES_ACC= $(COMMON) $(wildcard lib/aes_acc/aes*.c) my_ev.cpp -isystem libev
PCAP="-lpcap"
MP="-DUDP2RAW_MP"


NAME=udp2raw

TARGETS=amd64 arm amd64_hw_aes arm_asm_aes mips24kc_be mips24kc_be_asm_aes x86 x86_asm_aes mips24kc_le mips24kc_le_asm_aes

TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/${NAME}_\1/g'` version.txt

TARGETS_MP= mingw_cross mingw_cross_wepoll mac_cross

export STAGING_DIR=/tmp/    #just for supress warning of staging_dir not define

# targets for nativei (non-cross) compile 
all:git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb -static -O2

#dynamic link
dynamic: git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${FLAGS} -lrt -O2

#targes for general cross compile

cross:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O2

cross2:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O2

cross3:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O2

#targets only for debug purpose
fast: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb
debug: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG  -ggdb
debug2: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -ggdb -fsanitize=address

#targets only for 'make release'

mips24kc_be: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2
mips24kc_be_asm_aes: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O2 lib/aes_acc/asm/mips_be.S
mips24kc_le: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2
mips24kc_le_asm_aes: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O2 lib/aes_acc/asm/mips.S
amd64:git_version
	${cc_amd64}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
amd64_hw_aes:git_version
	${cc_amd64}   -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/x64.S -lgcc_eh -ggdb
x86:git_version
	${cc_x86}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
x86_asm_aes:git_version
	${cc_x86}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/x86.S -lgcc_eh -ggdb
arm:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh
arm_asm_aes:git_version
	${cc_arm}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/arm.S -lgcc_eh

release: ${TARGETS}
	cp git_version.h version.txt
	tar -zcvf ${TAR}

#targets for multi-platform version (native compile)
cygwin:git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -lrt -ggdb -static -O2 -D_GNU_SOURCE

mingw:git_version
	${cc_local}   -o ${NAME}_$@         -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32

mingw_wepoll:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES0} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -DNO_LIBEV_EMBED -D_WIN32 -lev -lws2_32

linux:git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -O2

freebsd:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -O2

mac:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES} ${PCAP} ${FLAGS} -ggdb -O2

#targets for multi-platform version (cross compile)

mingw_cross:git_version
	${cc_mingw_cross}   -o ${NAME}_mp.exe          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32 ${MP}

mingw_cross_wepoll:git_version
	${cc_mingw_cross}   -o ${NAME}_mp_wepoll.exe   -I. ${SOURCES0} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -DNO_LIBEV_EMBED -D_WIN32 -lev -lws2_32 ${MP}

mac_cross:git_version
	${cc_mac_cross}   -o ${NAME}_mp_mac            -I. ${SOURCES} ${PCAP} ${FLAGS} -ggdb -O2 ${MP}

release_mp:${TARGETS_MP}
	cp git_version.h version.txt
	tar -zcvf ${NAME}_mp_binaries.tar.gz ${NAME}_mp.exe ${NAME}_mp_wepoll.exe ${NAME}_mp_mac version.txt


clean:	
	rm -f ${TAR}
	rm -f ${NAME} ${NAME}_cross ${NAME}.exe ${NAME}_wepoll.exe ${NAME}_mac
	rm -f ${NAME}_mp_binaries.tar.gz ${NAME}_mp.exe ${NAME}_mp_wepoll.exe ${NAME}_mp_mac
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
