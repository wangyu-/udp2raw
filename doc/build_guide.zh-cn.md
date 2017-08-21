# udp2raw编译方法
本文演示怎么把udp2raw编译到自己所需的平台。

## 可以本地编译的linux平台
比如电脑、树莓派

##### 首先安装git
debian/ubuntun执行：
```
sudo apt-get install git
```
redhat/centos执行:
```
sudo yum install git
```
##### 用git把源码clone至本地

在任意目录执行：

```
git clone https://github.com/wangyu-/udp2raw-tunnel.git
cd udp2raw-tunnel
```

##### 安装g++ make 等工具
debian/ubuntun执行：
```
sudo apt-get install build-essential
```

redhat/centos执行:
```
sudo yum groupinstall 'Development Tools'
```

然后运行make，编译完成。 生成的udp2raw就是编译好的bianry。

## 需要交叉编译的平台
比如各种openwrt路由器

##### 首先安装git
debian/ubuntun执行：
```
sudo apt-get install git
```
redhat/centos执行:
```
sudo yum install git
```

##### 下载安装交叉编译工具包
去downloads.openwrt.org上找到自己的openwrt版本和cpu型号对应的SDK。通常openwrt版本号不一样也问题不大，最主要是cpu型号。

比如我的tplink wdr4310运行的是chaos_calmer 15.05,ar71xx cpu，应该下载这个包：

```
http://downloads.openwrt.org/chaos_calmer/15.05/ar71xx/generic/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64.tar.bz2
```
解压到本地任意目录，比如：/home/wangyu/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2

让后依次进入，staging_dir ，toolchain-xxxxx ，bin 目录，找到后缀是g++的软链,比如我的是mips-openwrt-linux-g++ ，记下这个文件的完整路径：

```
/home/wangyu/Desktop/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
```
##### 编译
把makefile的第一行 cross_cc=后面的内容改成你刚才记下的完整路径：
```
cc_cross=/home/wangyu/Desktop/OpenWrt-SDK-15.05-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
```

执行`make cross`，目录下生成udp2raw_cross文件。编译完成。

`make cross`编译出的binary是非静态的。如果运行有问题，可以尝试用`make cross2`或`make cross3`编译静态的binary,你的工具链必须带静态库才能成功编译,生成的文件仍然叫udp2raw_cross.
