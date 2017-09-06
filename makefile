cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
cc_mips34kc=/toolchains/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
#cc_arm= /toolchains/gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-g++ -march=armv6 -marm 
cc_arm= /toolchains/arm-2014.05/bin/arm-none-linux-gnueabi-g++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 
FLAGS= -std=c++11 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers

SOURCES=main.cpp lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp  -lpthread
SOURCES_AES_ACC=$(filter-out lib/aes.c,$(SOURCES)) $(wildcard lib/aes_acc/aes*.c)

NAME=udp2raw
TARGETS=amd64 mips34kc arm amd64_hw_aes arm_asm_aes mips34kc_asm_aes x86 x86_asm_aes
TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/udp2raw_\1/g'`

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

mips34kc: git_version
	${cc_mips34kc}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3

mips34kc_asm_aes: git_version
	${cc_mips34kc}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O3 lib/aes_acc/asm/mips_be.S

#bcm2708:
#	${cc_bcm2708} -o ${NAME}_bcm2708  -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64:git_version
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64_hw_aes:git_version
	${cc_local}   -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/x64.S
x86:git_version
	${cc_local}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O3 -m32
x86_asm_aes:git_version
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 -m32 lib/aes_acc/asm/x86.S
arm:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O3

arm_asm_aes:git_version
	${cc_arm}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/arm.S

cross:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O3

cross2:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O3   

cross3:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O3

release: ${TARGETS} 
	tar -zcvf ${TAR}

clean:	
	rm -f ${TAR}
	rm -f udp2raw udp2raw_cross udp2raw_cmake
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
	
