Udp2raw-tunnel 
![image2](/images/image2.PNG)
加密、防重放攻击的、信道复用的udp tunnel，利用raw socket中转udp流量

[English](/README.md)

[udp2raw+kcptun step_by_step教程](kcptun_step_by_step.md)

[udp2raw+finalspeed step_by_step教程](finalspeed_step_by_step.md)
### 把udp流量伪装成tcp /icmp
用raw socket给udp包加上tcp/icmp包头，可以突破udp流量限制或Udp QOS。或者在udp nat有问题的环境下，提升稳定性。  另外也支持用raw 发udp包，这样流量不会被伪装，只会被加密。

### 加密 防重放攻击
用aes128cbc加密，md5/crc32做数据完整校验。用类似ipsec/openvpn的 replay windows机制来防止重放攻击。

设计目标是，即使攻击者可以监听到tunnel的所有包，可以选择性丢弃tunnel的任意包，可以重放任意包；攻击者也没办法获得tunnel承载的任何数据，也没办法向tunnel的数据流中通过包构造/包重放插入任何数据。

### 模拟TCP3次握手
模拟TCP3次握手，模拟seq ack过程。另外还模拟了一些tcp option：MSS,sackOk,TS,TS_ack,wscale，用来使流量看起来更像是由普通的linux tcp协议栈发送的。

### 连接保持，连接快速恢复
心跳机制检查连接是否中断，一旦心跳超时。client会立即换raw socket的端口重连，重连成功后会恢复之前中断的连接。虽然raw端的端口变了，但是udp端的所有连接都会继续有效。udp这边感觉不到raw端的重连，只会感觉到短暂断流,这跟普通的短暂丢包是类似的，不会导致上层应用重连。

另一个优化是，重连只需要client发起，就可以立即被server处理，不需要等到server端的连接超时后。这个在单向连接失效的情况下有用。

另外，对于有大量client的情况，对于不同client,server发送的心跳是错开时间发送的，不会因为短时间发送大量的心跳而造成拥塞和延迟抖动。

### 其他特性
信道复用，client的udp端支持多个连接。

server支持多个client，也能正确处理多个连接的重连和连接恢复。

NAT 穿透 ，tcp icmp udp模式都支持nat穿透。

支持Openvz，配合finalspeed使用，可以在openvz上用tcp模式的finalspeed

支持Openwrt,没有编译依赖，容易编译到任何平台上。release中提供了ar71xx版本的binary

单进程，纯异步，无锁，高并发，除了回收过期连接外，所有操作的时间复杂度都跟连接数无关。回收过期连接这个操作是个批量操作，会定期进行，但是会保证一次回收的数量不超过总数的1/10（可配置），不会造成延迟抖动。

### 关键词
突破udp qos,突破udp屏蔽，openvpn tcp over tcp problem,openvpn over icmp,udp to icmp tunnel,udp to tcp tunnel,udp via icmp,udp via tcp

# 简明操作说明

### 环境要求
Linux主机，有root权限。主机上最好安装了iptables命令(apt/yum很容易安装)。在windows和mac上可以开虚拟机（桥接模式测试可用）。

### 安装
下载编译好的二进制文件，解压到任意目录。

https://github.com/wangyu-/udp2raw-tunnel/releases

### 运行
假设你有一个server，ip为44.55.66.77，有一个服务监听在udp 7777端口。 假设你本地的主机到44.55.66.77的UDP流量被屏蔽了，或者被qos了

```
在client端运行:
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -a -k "passwd" --raw-mode faketcp

在server端运行:
./udp2raw_amd64 -s -l0.0.0.0:4096 -r 127.0.0.1:7777  -a -k "passwd" --raw-mode faketcp

```

现在client和server之间建立起了，tunnel。想要在本地连接44.55.66.77:7777，只需要连接 127.0.0.1:3333。来回的所有的udp流量会被经过tunneling发送。在外界看起来是tcp流量，不会有udp流量暴露到公网。

# 进阶操作说明

### 命令选项
```
udp2raw-tunnel
version: Aug  5 2017 21:03:54
repository: https://github.com/wangyu-/udp2raw-tunnel

usage:
    run as client : ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]
    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]

common options,these options must be same on both side:
    --raw-mode            <string>        avaliable values:faketcp(default),udp,icmp
    -k,--key              <string>        password to gen symetric key,default:"secret key"
    --auth-mode           <string>        avaliable values:aes128cbc(default),xor,none
    --cipher-mode         <string>        avaliable values:md5(default),crc32,simple,none
    -a,--auto-rule                        auto add (and delete) iptables rule
    -g,--gen-rule                         generate iptables rule then exit
    --disable-anti-replay                 disable anti-replay,not suggested
client options:
    --source-ip           <ip>            force source-ip for raw socket
    --source-port         <port>          force source-port for raw socket,tcp/udp only
                                          this option disables port changing while re-connecting
other options:
    --log-level           <number>        0:never    1:fatal   2:error   3:warn 
                                          4:info (default)     5:debug   6:trace
    --log-position                        enable file name,function name,line number in log
    --disable-color                       disable log color
    --disable-bpf                         disable the kernel space filter,most time its not necessary
                                          unless you suspect there is a bug
    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024
    --seqmode             <number>        seq increase mode for faketcp:
                                          0:dont increase
                                          1:increase every packet
                                          2:increase randomly, about every 3 packets (default)
    -h,--help                             print this help message
```
### iptables 规则
用raw收发tcp包本质上绕过了linux内核的tcp协议栈。linux碰到raw socket发来的包会不认识，如果一直收到不认识的包，会回复大量RST，造成不稳定或性能问题。所以强烈建议添加iptables规则屏蔽Linux内核的对指定端口的处理。用-a选项，udp2raw会在启动的时候自动帮你加上Iptables规则，退出的时候再自动删掉。如果你不信任-a选项的可靠性，可以用-g选项来生成相应的Ip规则再自己手动添加。

用raw收发udp包也类似，只是内核回复的是icmp unreachable。而用raw 收发icmp，内核会自动回复icmp echo。都需要相应的iptables规则。
### cipher-mode 和 auth-mode 
如果要最大的安全性建议用aes128cbc+md5。如果要运行再路由器上，建议xor+simple。但是注意xor+simple只能骗过防火墙的包检测，不能防止真正的攻击者。

### seq-mode
facktcp模式并没有模拟tcp的全部。所以理论上有办法把faketcp和真正的tcp流量区分开来（虽然大部分ISP不太可能做这种程度的包检测）。seq-mode可以改变一些seq ack的行为。如果遇到了连接问题，可以尝试更改。在我这边的移动线路用3种模式都没问题。

# 性能测试
iperf3 的UDP模式有BUG，所以，这里用iperf3的tcp模式，配合Openvpn，测试udp2raw的性能。（iperf3 udp issue ,https://github.com/esnet/iperf/issues/296 ）

openvpn关掉了自带的加密。
#### iperf3 命令: 
```
iperf3 -c 10.222.2.1 -P40 
iperf3 -c 10.222.2.1 -P40 -R
```
#### client主机
vultr 2.5美元每月套餐(single core 2.4ghz cpu,512m ram,日本东京机房),
#### server主机
bandwagonhost 3.99美元每年套餐(single core 2.0ghz cpu,128m ram,美国洛杉矶机房)
### 测试1
raw_mode: faketcp  cipher_mode: xor  auth_mode: simple

![image4](/images/image4.PNG)

（反向的速度几乎一样，所以只发正向测试的图)

测试中cpu被打满。其中有30%的cpu是被openvpn占的。 如果不用Openvpn中转，实际达到100+Mb/S 应该没问题。

### 测试2
raw_mode: faketcp  cipher_mode: aes128cbc  auth_mode: md5

![image5](/images/image5.PNG)

（反向的速度几乎一样，所以只发正向测试的图)

测试中cpu被打满。绝大多数cpu都是被udp2raw占用的（主要消耗在aes加密）。即使不用Openvpn，速度也不会快很多了。
# 应用
### 中转 kcptun
[udp2raw+kcptun step_by_step教程](kcptun_step_by_step.md)
### 中转 finalspeed
[udp2raw+finalspeed step_by_step教程](finalspeed_step_by_step.md)
# 相关repo
### kcptun-raw
this project was inspired by kcptun-raw,which modified kcptun to support tcp mode.

https://github.com/Chion82/kcptun-raw
### kcpraw
another project of kcptun with tcp mode

https://github.com/ccsexyz/kcpraw
### relayRawSocket
a simple  udp to raw tunnel without simluated 3-way handshake ,wrote in python

https://github.com/linhua55/some_kcptun_tools/tree/master/relayRawSocket
### icmptunnel
Transparently tunnel your IP traffic through ICMP echo and reply packets.

https://github.com/DhavalKapil/icmptunnel

