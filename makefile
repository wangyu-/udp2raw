cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
#cc_local=/opt/cross/x86_64-linux-musl/bin/x86_64-linux-musl-g++
#cc_mips34kc=/toolchains/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
cc_mips24kc_be=/toolchains/lede-sdk-17.01.2-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-g++
cc_mips24kc_le=/toolchains/lede-sdk-17.01.2-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.16/bin/mipsel-openwrt-linux-musl-g++
#cc_arm= /toolchains/gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-g++ -march=armv6 -marm 
cc_arm= /toolchains/arm-2014.05/bin/arm-none-linux-gnueabi-g++
#cc_arm=/toolchains/lede-sdk-17.01.2-brcm2708-bcm2708_gcc-5.4.0_musl-1.1.16_eabi.Linux-x86_64/staging_dir/toolchain-arm_arm1176jzf-s+vfp_gcc-5.4.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-muslgnueabi-g++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 
cc_tmp= /home/wangyu/OpenWrt-SDK-15.05-x86-64_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-4.8-linaro_uClibc-0.9.33.2/bin/x86_64-openwrt-linux-uclibc-g++
cc_mingw_cross=i686-w64-mingw32-g++-posix

FLAGS= -std=c++11 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT}

COMMON=main.cpp lib/md5.cpp encrypt.cpp log.cpp network.cpp common.cpp  connection.cpp misc.cpp fd_manager.cpp client.cpp -lpthread

PCAP="-lpcap"

LIBNET=-D_DEFAULT_SOURCE `libnet-config --defines` `libnet-config --libs`


SOURCES0= $(COMMON) lib/aes_faster_c/aes.cpp lib/aes_faster_c/wrapper.cpp lib/pbkdf2-sha1.cpp lib/pbkdf2-sha256.cpp
SOURCES=${SOURCES0} my_ev.cpp -isystem libev
SOURCES_TINY_AES= $(COMMON) lib/aes.cpp
SOURCES_AES_ACC=$(COMMON) $(wildcard lib/aes_acc/aes*.c)

NAME=udp2raw_mp
OUTPUTS=${NAME} ${NAME}_nolibnet ${NAME}.exe ${NAME}_nolibnet.exe

TARGETS=amd64 arm amd64_hw_aes arm_asm_aes mips24kc_be mips24kc_be_asm_aes x86 x86_asm_aes mips24kc_le mips24kc_le_asm_aes
TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/udp2raw_\1/g'` version.txt

all:git_version
	echo "\ndo not use 'make all', instead, use 'make linux' 'make mac' 'make freebsd' 'make cygwin' \nyou can also try 'make linux_nolibnet' 'make mac_nolibnet'  'make freebsd_nolibnet'  "

cygwin:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}_nolibnet          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -lrt -ggdb -static -O2 -D_GNU_SOURCE

mingw:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}_nolibnet          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32

mingw_cross:git_version
	${cc_mingw_cross}   -o ${NAME}_nolibnet.exe          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32

mingw_cross_wepoll:git_version
	${cc_mingw_cross}   -o ${NAME}_nolibnet_wepoll.exe          -I. ${SOURCES0} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -DNO_LIBEV_EMBED -D_WIN32 -lev -lws2_32

linux:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${PCAP} ${LIBNET} ${FLAGS} -lrt -ggdb -static -O2

linux_nolibnet:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}_nolibnet          -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -O2 -DNO_LIBNET

freebsd:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${PCAP} ${LIBNET} ${FLAGS} -lrt -ggdb -static -O2

freebsd_nolibnet:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}_nolibnet         -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -O2 -DNO_LIBNET

mac:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${PCAP} ${LIBNET} ${FLAGS} -ggdb -O2

mac_nolibnet:git_version
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}_nolibnet          -I. ${SOURCES} ${PCAP} ${FLAGS} -ggdb -O2 -DNO_LIBNET

mac_nolibnet_static:git_version  #it doesnt work
	rm -f ${OUTPUTS}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} -static-libstdc++  /usr/local/Cellar/libpcap/1.8.1/lib/libpcap.a  ${FLAGS} -ggdb -O2 -DNO_LIBNET

fast: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb
debug: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${PCAP} ${LIBNET} ${FLAGS} -lrt -ggdb -static -O2 -Wformat-nonliteral -D MY_DEBUG 
debug2: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -ggdb

#dynamic: git_version
#	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${FLAGS} -lrt -O3

clean:	
	rm -f udp2raw.exe ${OUTPUTS}
	rm -f udp2raw udp2raw_cross udp2raw_cmake udp2raw_dynamic
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
