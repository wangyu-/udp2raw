cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
cc_ar71xx=/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 
cc_arm=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
FLAGS= -std=c++11 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers

SOURCES=main.cpp lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -lpthread
SOURCES_AES_ACC=$(filter-out lib/aes.c,$(SOURCES)) $(wildcard lib/aes_acc/aes*.c)

NAME=udp2raw
TAR=${NAME}_binaries.tar.gz ${NAME}_amd64  ${NAME}_x86  ${NAME}_x86_asm_aes ${NAME}_ar71xx ${NAME}_bcm2708 ${NAME}_arm ${NAME}_amd64_hw_aes ${NAME}_arm_asm_aes ${NAME}_ar71xx_asm_aes

all:
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt  -static -O3
fast:
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt
debug:
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG 

ar71xx: 
	${cc_ar71xx}  -o ${NAME}_ar71xx   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3

ar71xx_asm_aes: 
	${cc_ar71xx}  -o ${NAME}_ar71xx_asm_aes   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O3 lib/aes_acc/asm/mips_be.S

bcm2708:
	${cc_bcm2708} -o ${NAME}_bcm2708  -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64:
	${cc_local}   -o ${NAME}_amd64    -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64_hw_aes:
	${cc_local}   -o ${NAME}_amd64_hw_aes   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/x64.S
x86:
	${cc_local}   -o ${NAME}_x86      -I. ${SOURCES} ${FLAGS} -lrt -static -O3 -m32
x86_asm_aes:
	${cc_local}   -o ${NAME}_x86_asm_aes    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 -m32 lib/aes_acc/asm/x86.S
arm:
	${cc_cross}   -o ${NAME}_arm      -I. ${SOURCES} ${FLAGS} -lrt -static -O3

arm_asm_aes:
	${cc_cross}   -o ${NAME}_arm_asm_aes    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O3 lib/aes_acc/asm/arm.S

cross:
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O3

cross2:
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O3   

cross3:
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O3

release: amd64 x86 ar71xx bcm2708 arm amd64_hw_aes arm_asm_aes x86_asm_aes ar71xx_asm_aes
	tar -zcvf ${TAR}

clean:	
	rm -f ${TAR}
	rm -f udp2raw udp2raw_cross udp2raw_cmake
	
