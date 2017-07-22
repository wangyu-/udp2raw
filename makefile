ccmips=mips-openwrt-linux-g++
all:
	killall raw||true
	sleep 1
	g++ main.cpp -o raw -static -lrt -ggdb -I. aes.c md5.c encrypt.cpp -O3 
#	${ccmips} -std=c++11 main.cpp -o rawmips -static -lrt -ggdb -I. aes.c md5.c encrypt.cpp -O3 -lstdc++

