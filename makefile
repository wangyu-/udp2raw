ccmips=mips-openwrt-linux-g++
FLAGS=-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter
FLAGS2= -O3
all:
	sudo killall udp2raw||true
	sleep 0.2
	g++ main.cpp -o udp2raw_amd64 -static  -ggdb -I. -Ilib lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} ${FLAGS2}
	${ccmips} main.cpp -o udp2raw_ar71xx  -lrt -I. -Ilib lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -std=c++11 ${FLAGS} ${FLAGS2}
fast:
	sudo killall udp2raw||true
	sleep 0.2
	g++ main.cpp -o udp2raw_amd64 -ggdb -I. -Ilib lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} 


debug:
	g++ main.cpp -o udp2raw_amd64 -static  -ggdb -I. -Ilib lib/aes.c lib/md5.c encrypt.cpp log.cpp network.cpp common.cpp -lrt -std=c++11    ${FLAGS} -Wformat-nonliteral -D MY_DEBUG
