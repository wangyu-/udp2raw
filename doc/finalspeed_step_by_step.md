# udp2raw+finalspeed 加速tcp流量 Step by Step 教程
![image](finalspeed_step_by_step/Capture0.PNG)

##### 背景
国内有些ISP会对UDP做QOS或屏蔽，这时候加速协议对TCP发包模式的支持就很重要。finalspeed虽然本身支持在底层用TCP发包，但是其依赖的libpcap不支持openvz架构，即使不是openvz架构的主机，也存在不稳定的问题。


##### 摘要
udp2raw是一个把udp流量通过raw socket包装成tcp流量的工具。通过用udp2raw配合udp模式的 finalspeed一样可以达到在底层发tcp包，绕过QOS的效果。支持openvz,稳定性也好很多。原理上相当于在finalspeed外面再包了一层tunnel。

本教程会一步一步演示用udp2raw+finalspeed加速http流量的过程。加速任何其他tcp流量也一样，包括ss。本文避免讨论科学上网，所以只演示加速http流量。

udp2raw也支持把udp流量包装成Icmp发送，本教程不做演示。

### 环境要求
服务器主机是linux，有root权限。  可以是openvz架构的vps。 也可以是openwrt路由器。

本地主机是windows,本地有openwrt路由器或树莓派或安装了linux虚拟机（网卡设置为桥接模式）。

(如果嫌给虚拟机安装linux麻烦，可以用release里发布的预装了udp2raw的openwrt_x86虚拟机镜像，容量4.4mb)

下面的教程按虚拟机演示，如果你有openwrt路由器或树莓派，可以直接运行再路由器或树莓派上，就不需要虚拟机了。

### 安装
下载好udp2raw的压缩包，解压分别解压到服务器和本地的虚拟机。

https://github.com/wangyu-/udp2raw-tunnel/releases

在服务器端安装好finalspeed服务端，在本地windows安装好finalspeed的客户端。服务端我以前是用91yun的一键安装脚本安装的，没装过的可以去网上搜一键安装脚本。


### 安全

使用 ROOT 运行 `udp2raw` 可能带来安全隐患，因此，以下 `udp2raw` 命令将全部以非 ROOT 用户执行。请先阅读 [这个文档](/README.md#security-important) 以确保以下指令能够正确执行。

### 运行
1.先在服务器主机运行如下命令，确定finalspeed服务端已经正常启动了。

```
netstat -nlp|grep java
```
![image](finalspeed_step_by_step/Capture5.PNG)

如果显示了150端口，就表示服务端启动好了。

2.在服务器启动udp2raw server
```
sudo iptables -I INPUT -p tcp --dport 8855 -j DROP
 ./udp2raw_amd64 -s -l0.0.0.0:8855 -r 127.0.0.1:150 -k "passwd" --raw-mode faketcp
```
![image](finalspeed_step_by_step/Capture2.PNG)

3.在本地的虚拟机上启动udp2raw client  ,假设服务器ip是45.66.77.88
```
sudo iptables -I INPUT -s 45.66.77.88 -p tcp --sport 8855 -j DROP
./udp2raw_amd64 -c -r45.66.77.88:8855 -l0.0.0.0:150 --raw-mode faketcp -k"passwd"
```
如果一切正常，client端会显示client_ready:

![image](finalspeed_step_by_step/Capture3.PNG)

记下红框中的ip,这是虚拟机的网卡ip

在server端也会显示server_ready
![image](finalspeed_step_by_step/Capture4.PNG)

4.在本地windows,按图配置好finalspeed的客户端。注意，192.168.205.8改成你刚才记下来的IP，带宽也要按实际的填。传输协议要选UDP.
![image](finalspeed_step_by_step/Capture.PNG)

5.所有准备工作已经完成了，在本地访问本地的8012端口，相当于访问服务器的80端口。

来试一下通过http://127.0.0.1:8012/ 下载文件 ，1.5M/s：
![image](finalspeed_step_by_step/Capture6.PNG)

再试一下直接通过服务器的ip访问，http://45.66.77.88:80/ ，速度只有600K/s
![image](finalspeed_step_by_step/Capture7.PNG)

教程就到这里了，用来加速其他的tcp服务也是一样的，只要再第三步那里设置其他的端口。
