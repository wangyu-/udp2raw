# udp2raw build guide

the guide on how to build udp2raw to you own platform

## linux platform which supports local compile
such as PC,raspberry pi

##### install git
run on debian/ubuntun：
```
sudo apt-get install git
```
run on redhat/centos:
```
sudo yum install git
```
##### clone git code

run in any dir：

```
git clone https://github.com/wangyu-/udp2raw-tunnel.git
cd udp2raw-tunnel
```

##### install compile tool
run on debian/ubuntun：
```
sudo apt-get install build-essential
```

run on redhat/centos:
```
sudo yum groupinstall 'Development Tools'
```

run 'make'，compilation done. the udp2raw file is the just compiled binary

## platform which needs cross-compile
such as openwrt router,run following instructions on your PC

##### install git
run on debian/ubuntun：
```
sudo apt-get install git
```
run on redhat/centos:
```
sudo yum install git
```

##### download cross compile tool chain

find it on downloads.openwrt.org according to your openwrt version and cpu model.

for example, my tplink wdr4310 runs chaos_calmer 15.05,its with ar71xx cpu，download the following package.

```
http://downloads.openwrt.org/chaos_calmer/15.05/ar71xx/generic/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64.tar.bz2
```
unzip it to any dir,such as ：/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2

cd into staging_dir ，toolchain-xxxxx ，bin .find the soft link with g++ suffix. in my case ,its mips-openwrt-linux-g++ ,check for its full path:

```
/home/wangyu/Desktop/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
```
##### compile
modify first line of makefile to:
```
cc_cross=/home/wangyu/Desktop/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
```

run `make cross`，the just generated `udp2raw_cross` is the binary,compile done. copy it to your router to run.

`make cross` generates non-static binary. If you have any problem on running it,try to compile a static binary by using `make cross2` or `make cross3`.If your toolchain supports static compiling, usually one of them will succeed. The generated file is still named `udp2raw_cross`.
