ccmips=mips-openwrt-linux-g++
FLAGS=-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter
all:
	sudo killall udp2raw||true
	sleep 0.2
	g++ main.cpp -o udp2raw -static  -ggdb -I. aes.c md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS}
	${ccmips} main.cpp -o udp2raw_mips  -lrt -I. aes.c md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS}


