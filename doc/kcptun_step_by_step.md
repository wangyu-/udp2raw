# udp2raw+kcptun 加速tcp流量 Step by Step 教程
![image](kcptun_step_by_step/Capture00.PNG)

本教程会一步一步演示用udp2raw+kcptun加速SSH流量的过程。加速任何其他tcp流量也一样，包括ss；本文避免涉及科学上网，所以演示ssh。

### 环境要求
两边的主机都是linux，有root权限。 可以是openwrt路由器或树莓派，也可以是root了的android。

(windows和mac可以用release里发布的预装了udp2raw的openwrt_x86虚拟机镜像，容量4.4mb,开机即用)


### 安装
下载好kcptun和udp2raw的压缩包，解压分别解压到client端和server端。

https://github.com/xtaci/kcptun/releases
https://github.com/wangyu-/udp2raw-tunnel/releases

解压好后，如图：
![image](kcptun_step_by_step/Capture0.PNG)

### 安全

使用 ROOT 运行 `udp2raw` 可能带来安全隐患，因此，以下 `udp2raw` 命令将全部以非 ROOT 用户执行。请先阅读 [这个文档](/README.md#security-important) 以确保以下指令能够正确执行。

### 运行
1.在远程服务器运行 udp2raw_amd64 server模式：
```bash
sudo iptables -I INPUT -p tcp --dport 8855 -j DROP
./udp2raw_amd64 -s -l0.0.0.0:8855 -r 127.0.0.1:4000 -k "passwd" --raw-mode faketcp
```
![image](kcptun_step_by_step/Capture.PNG)

2.在本地运行udp2raw_amd64 client模式，假设server ip是45.66.77.88：
```bash
sudo iptables -I INPUT -p tcp -s 45.66.77.88 --sport 8855 -j DROP
./udp2raw_amd64 -c -r45.66.77.88:8855 -l0.0.0.0:4000 --raw-mode faketcp -k"passwd"
```
如果一切正常client端输出如下，显示client_ready：
![image](kcptun_step_by_step/Capture2.PNG)

server端也会有类似输出,显示server_ready：
![image](kcptun_step_by_step/Capture3.PNG)

3.在远程服务器运行 kcp server


```
./server_linux_amd64 -t "127.0.0.1:22" -l ":4000" -mode fast2 -mtu 1300
```
-mtu 1300很重要，或者设置成更小。
![image](kcptun_step_by_step/Capture6.PNG)

4.在本地运行 


```
 ./client_linux_amd64 -r "127.0.0.1:4000" -l ":3322" -mode fast2 -mtu 1300
```
-mtu 1300很重要，或者设置成更小。
![image](kcptun_step_by_step/Capture7.PNG)

5.所有准备工作已经做好，在本地运行
```
ssh -p 3322 root@127.0.0.1
```
已经连进去了，而且是经过kcptun加速的：
![image](kcptun_step_by_step/Capture8.PNG)
