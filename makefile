cc_cross=/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
cc_local=g++
cc_ar71xx=/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 
FLAGS= -std=c++11 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter
SOURCES=main.cpp lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp
TAR=udp2raw_binaries.tar.gz udp2raw_amd64  udp2raw_x86  udp2raw_ar71xx udp2raw_bcm2708

all:
	rm -f udp2raw
	${cc_local}   -o udp2raw          -I. ${SOURCES} ${FLAGS} -lrt  -static -O3
fast:
	rm -f udp2raw
	${cc_local}   -o udp2raw          -I. ${SOURCES} ${FLAGS} -lrt
debug:
	rm -f udp2raw
	${cc_local}   -o udp2raw          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG 

ar71xx: 
	${cc_ar71xx}  -o udp2raw_ar71xx   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O3
bcm2708:
	${cc_bcm2708} -o udp2raw_bcm2708  -I. ${SOURCES} ${FLAGS} -lrt -static -O3
amd64:
	${cc_local}   -o udp2raw_amd64    -I. ${SOURCES} ${FLAGS} -lrt -static -O3
x86:
	${cc_local}   -o udp2raw_x86      -I. ${SOURCES} ${FLAGS} -lrt -m32 -static -O3

cross:
	${cc_cross}   -o udp2raw_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O3   

cross2:
	${cc_cross}   -o udp2raw_cross    -I. ${SOURCES} ${FLAGS} -lrt -O3

release: amd64 x86 ar71xx bcm2708
	tar -zcvf ${TAR}

clean:	
	rm -f ${TAR}
	
