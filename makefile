ccmips=mips-openwrt-linux-g++
all:
	killall udp2raw||true
	sleep 1
	g++ main.cpp -o udp2raw -static -lrt -ggdb -I. aes.c md5.c encrypt.cpp log.cpp -O3  -std=c++11
	${ccmips} -O3 main.cpp -o udp2raw_mips  -lrt   -I. aes.c md5.c encrypt.cpp log.cpp -std=c++11


