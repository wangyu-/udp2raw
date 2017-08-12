cc_cross=/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
FLAGS=-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter
FLAGS2= -O3
all:
	sudo killall udp2raw||true
	sleep 0.2
	gcc main.cpp -o udp2raw  -static  -ggdb -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} ${FLAGS2}
#	${ccmips} main.cpp -o udp2raw_ar71xx  -lrt -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} ${FLAGS2}
fast:
	sudo killall udp2raw||true
	sleep 0.2
	g++ main.cpp -o udp2raw -ggdb -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} 


debug:
	g++ main.cpp -o udp2raw -static  -ggdb -I. -Ilib lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} -Wformat-nonliteral -D MY_DEBUG
cross:
	${cc_cross} main.cpp -o udp2raw_ar71xx  -lrt -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} ${FLAGS2}
cross2:
	${cc_cross} main.cpp -o udp2raw_ar71xx  -lrt -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} -static -lgcc_eh -O3
cross3:
	${cc_cross} main.cpp -o udp2raw_ar71xx  -lrt -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} -static -lgcc_eh

release:
	g++ main.cpp -o udp2raw_amd64  -static  -ggdb -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} ${FLAGS2}
	g++ main.cpp -o udp2raw_x86  -static -ggdb -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} ${FLAGS2} -m32
	${cc_cross} main.cpp -o udp2raw_ar71xx  -lrt -I. lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} -static -lgcc_eh -O3
	tar -zcvf udp2raw_binaries.tar.gz udp2raw_amd64  udp2raw_x86  udp2raw_ar71xx
	
