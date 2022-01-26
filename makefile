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

FLAGS= -std=c++11 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT}

COMMON=main.cpp lib/chacha20.c lib/md5.cpp lib/pbkdf2-sha1.cpp lib/pbkdf2-sha256.cpp encrypt.cpp log.cpp network.cpp common.cpp  connection.cpp misc.cpp fd_manager.cpp client.cpp server.cpp -lpthread my_ev.cpp -isystem libev
SOURCES= $(COMMON) lib/aes_faster_c/aes.cpp lib/aes_faster_c/wrapper.cpp
SOURCES_TINY_AES= $(COMMON) lib/aes.c
SOURCES_AES_ACC=$(COMMON) $(wildcard lib/aes_acc/aes*.c)

NAME=udp2raw
TARGETS=amd64 arm amd64_hw_aes arm_asm_aes mips24kc_be mips24kc_be_asm_aes x86 x86_asm_aes mips24kc_le mips24kc_le_asm_aes
TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/udp2raw_\1/g'` version.txt

all:git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb -static -O3
fast: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb
debug: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG 
debug2: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -ggdb

dynamic: git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${FLAGS} -lrt -O3

tmp:git_version
	${cc_tmp}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3

mips24kc_be: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3
mips24kc_be_asm_aes: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O3 lib/aes_acc/asm/mips_be.S

mips24kc_le: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3
mips24kc_le_asm_aes: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O3 lib/aes_acc/asm/mips.S

#bcm2708:
#	${cc_bcm2708} -o ${NAME}_bcm2708  -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64:git_version
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O3

amd64_perf:git_version
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O0 -fno-omit-frame-pointer -g

amd64_hw_aes:git_version
	${cc_local}   -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/x64.S
x86:git_version
	${cc_local}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O3 -m32
x86_asm_aes:git_version
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 -m32 lib/aes_acc/asm/x86.S
arm:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O3

arm_perf:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -mapcs-frame -fno-omit-frame-pointer -g -O0 -lgcc_eh

arm_asm_aes:git_version
	${cc_arm}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/arm.S

cross:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O3

cross2:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O3   

cross3:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O3

release: ${TARGETS} 
	cp git_version.h version.txt
	tar -zcvf ${TAR}

clean:	
	rm -f ${TAR}
	rm -f udp2raw udp2raw_cross udp2raw_cmake udp2raw_dynamic
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
	
