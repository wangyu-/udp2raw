ccmips=mips-openwrt-linux-g++
all:
	killall raw||true
	sleep 1
	g++ main.cpp -o raw -static -lrt -ggdb -I. aes.c md5.c encryption.cpp
#	${ccmips} main.cpp -o rawmips   -static -lgcc_eh -lrt

