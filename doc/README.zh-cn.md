# Udp2raw-tunnel


A Tunnel which turns UDP Traffic into Encrypted FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment).

通过 Raw Socket 将 UDP 流量转换为加密的 假TCP/UDP/ICMP 流量的隧道，可帮助你绕过 UDP 防火墙/规避不稳定的 UDP 网络环境。

When used alone,udp2raw tunnels only UDP traffic. Nevertheless,if you used udp2raw + any UDP-based VPN together,you can tunnel any traffic(include TCP/UDP/ICMP),currently OpenVPN/L2TP/ShadowVPN and [tinyfecVPN](https://github.com/wangyu-/tinyfecVPN) are confirmed to be supported.

单独使用时，udp2raw隧道仅处理UDP流量。尽管如此，将基于 UDP 使用的 VPN 与 udp2raw 一起使用时，你可以代理任何流量（包括 TCP/UDP/ICMP），目前已确定支持的有 OpenVPN/L2TP/ShadowVPN 与 [tinyfecVPN](https://github.com/wangyu-/tinyfecVPN)

![image0](images/image0.PNG)

or

![image_vpn](images/udp2rawopenvpn.PNG)

[udp2raw wiki](https://github.com/wangyu-/udp2raw-tunnel/wiki)

[简体中文](/doc/README.zh-cn.md)


# Support Platforms

# 支持的平台

Linux host (including desktop Linux,Android phone/tablet,OpenWRT router,or Raspberry PI) with root account or cap_net_raw capability.

有 root 权限的，或者 cap_net_raw 支持的 Linux 设备（包括桌面电脑， Android 手机/平板， OpenWRT 路由器和树莓派）。

For Windows and MacOS users, use the udp2raw in [this repo](https://github.com/wangyu-/udp2raw-multiplatform).

对于 Windows 和 macOS 用户，使用[这个 Repo](https://github.com/wangyu-/udp2raw-multiplatform) 当中的udp2raw。

# Features

# 功能

### Send/Receive UDP Packets with ICMP/FakeTCP/UDP headers

### 收发有 ICMP/假TCP/UDP 标头的 UDP 数据包。

ICMP/FakeTCP headers help you bypass UDP blocking, UDP QOS or improper UDP NAT behavior on some ISPs. In ICMP header mode,udp2raw works like an ICMP tunnel.

ICMP/假TCP 标头帮助你绕过UDP封锁，UDP QoS 或者纠正由于部分 IPS 的 NAT 导致的 UDP 错误。。ICMP标头模式下， udp2raw 会像 ICMP 隧道一样工作。

UDP headers are also supported. In UDP header mode, it behaves just like a normal UDP tunnel, and you can just make use of the other features (such as encryption, anti-replay, or connection stabilization).

也支持UDP标头模式。在这个模式下，udp2raw 表现就像一个普通的 UDP 隧道，这时你可以使用其他udp2raw的功能，如加密，防重放，或者稳定性提升。

### Simulated TCP with Real-time/Out-of-Order Delivery

### 模拟实时/乱序 TCP 连接

In FakeTCP header mode,udp2raw simulates 3-way handshake while establishing a connection,simulates seq and ack_seq while data transferring. It also simulates a few TCP options such as: `MSS`, `sackOk`, `TS`, `TS_ack`, `wscale`. Firewalls will regard FakeTCP as a TCP connection, but its essentially UDP: it supports real-time/out-of-order delivery(just as normal UDP does), no congestion control or re-transmission. So there wont be any TCP over TCP problem when using OpenVPN.

在假TCP标头模式，udp2raw 会在建立连接时模拟TCP的三次握手，在数据传输时模拟 seq 和 ack_seq。udp2raw同样会模拟一些TCP Options如：`MSS`, `sackOk`, `TS`, `TS_ack`, `wscale`。防火墙会把这些假TCP流量认作TCP流量，但实际上它们是UDP：因为虽然它同样支持普通TCP的实时/乱序传输，但不支持重传或者堵塞控制。所以不必担心在使用 OpenVPN 时遇到 TCP over TCP 问题。

### Encryption, Anti-Replay

# 加密与防重放

* Encrypt your traffic with AES-128-CBC.
* 使用 AES-128-CBC 加密流量
* Protect data integrity by HMAC-SHA1 (or weaker MD5/CRC32).
* 使用 HMAC-SHA1 或者查错能力较差的 MD5/CRC32 保证数据完整性
* Defense replay attack with anti-replay window.
* 使用“滑动窗口”防止重放攻击

[Notes on encryption](https://github.com/wangyu-/udp2raw-tunnel/wiki/Notes-on-encryption)

[有关加密的内容](https://github.com/wangyu-/udp2raw-tunnel/wiki/Notes-on-encryption)

### Failure Dectection & Stabilization (Connection Recovery)

### 断线检测与稳定性提升（连接恢复）

Conection failures are detected by heartbeats. If timed-out, client will automatically change port number and reconnect. If reconnection is successful, the previous connection will be recovered, and all existing UDP conversations will stay vaild.

心跳包会检测连接是否断开。如果连接超时，客户端将会自动切换端口号并重新连接。如果重连成功，原连接将会恢复，现有所有的 UDP 封包仍保持有效。

For example, if you use udp2raw + OpenVPN, OpenVPN won't lose connection after any reconnect, **even if network cable is re-plugged or WiFi access point is changed**.

例如，如果将 udp2raw 和 OpenVPN 配合使用，**就算是重插网线或者更换 Wi-Fi** 之类的重连， OpenVPN 也不会丢失连接。

### Other Features

### 其他特性

* **Multiplexing** One client can handle multiple UDP connections, all of which share the same raw connection.

* **单线复用** 一个客户端可承载多路 UDP 连接，同时使用一个 Raw 连接。

* **Multiple Clients** One server can have multiple clients.

* **多客户端** 一个服务器可以被多个客户端连接。

* **NAT Support** All of the 3 modes work in NAT environments.

* **NAT 支持** 三种模式都支持 NAT 环境。

* **OpenVZ Support** Tested on BandwagonHost VPS.

* **OpenVZ 虚拟化支持** 已经在 BandwagonHost VPS上测试。

* **Easy to Build** No dependencies.To cross-compile udp2raw,all you need to do is just to download a toolchain,modify makefile to point at the toolchain,run `make cross` then everything is done.(Note:Pre-compiled binaries for Desktop,RaspberryPi,Android,some Openwrt Routers are already included in [Releases](https://github.com/wangyu-/udp2raw-tunnel/releases))

* **轻松构建** 没有依赖。跨平台编译 udp2raw 时，你只需要下载交叉编译链，修改 MAKEFILE 指向交叉编译链，运行 `make cross` 即可。（注：对于桌面端，树莓派，安卓与一部分 OpenWRT 路由器，预编译的可执行文件已经包含在  [Releases](https://github.com/wangyu-/udp2raw-tunnel/releases)。）

### Keywords

### 关键字

`Bypass UDP QoS` `Bypass UDP Blocking` `Bypass OpenVPN TCP over TCP problem` `OpenVPN over ICMP` `UDP to ICMP tunnel` `UDP to TCP tunnel` `UDP over ICMP` `UDP over TCP`

# Getting Started

# 快速开始

### Installing

### 安装

Download binary release from https://github.com/wangyu-/udp2raw-tunnel/releases

在 https://github.com/wangyu-/udp2raw-tunnel/releases 下载可执行文件。

### Running

### 运行

Assume your UDP is blocked or being QOS-ed or just poorly supported. Assume your server ip is 44.55.66.77, you have a service listening on udp port 7777.

假设你的 UDP 被封禁，被 QoS ，亦或只是支持较差。你有一台 IP 为 44.55.66.77 的服务器，上面有一个监听 UDP 端口 7777 的服务。

```bash
# 服务器
./udp2raw_amd64 -s -l0.0.0.0:4096 -r 127.0.0.1:7777    -k "passwd" --raw-mode faketcp -a

# 客户端
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096  -k "passwd" --raw-mode faketcp -a
```
(The above commands need to be run as root. For better security, with some extra steps, you can run udp2raw as non-root. Check [this link](https://github.com/wangyu-/udp2raw-tunnel/wiki/run-udp2raw-as-non-root) for more info  )

（上面的指令运行需要 root 。可以通过几个步骤，以非 root 运行 udp2raw 获得更好的安全性。 可点击 [这个链接](https://github.com/wangyu-/udp2raw-tunnel/wiki/run-udp2raw-as-non-root) 了解更多。）

###### Server Output:

###### 服务器输出
![](images/output_server.PNG)
###### Client Output:

###### 客户端输出
![](images/output_client.PNG)

Now,an encrypted raw tunnel has been established between client and server through TCP port 4096. Connecting to UDP port 3333 at the client side is equivalent to connecting to port 7777 at the server side. No UDP traffic will be exposed.

现在，在 TCP 端口 4096 上就建立起一个 raw 隧道。客户端对本地 UDP 端口 3333 的请求将会等同于请求服务器 UDP 端口 7777。没有任何暴露的 UDP 连接。

### Note

### 注
To run on Android, check [Android_Guide](/doc/android_guide.md)

在安卓上运行请参考[Android_Guide](/doc/android_guide.md)。

`-a` option automatically adds an iptables rule (or a few iptables rules) for you, udp2raw relies on this iptables rule to work stably. Be aware you dont forget `-a` (its a common mistake). If you dont want udp2raw to add iptables rule automatically, you can add it manually(take a look at `-g` option) and omit `-a`.

`-a` 参数会自动加入保证 udp2raw 稳定运行的一条或几条 iptables 规则。这是一个常见问题，所以注意运行时有没有 `-a` 参数。如果你不希望 udp2raw 自动添加 iptables 规则，你可以手动添加规则并不加入 `-a` 选项。（请参考参数 `-g` 的用法。）

# Advanced Topic
### Usage
```
udp2raw-tunnel
git version:6e1df4b39f    build date:Oct 24 2017 09:21:15
repository: https://github.com/wangyu-/udp2raw-tunnel

usage:
    run as client : ./this_program -c -l local_listen_ip:local_port -r server_address:server_port  [options]
    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_address:remote_port  [options]

common options,these options must be same on both side:
    --raw-mode            <string>        avaliable values:faketcp(default),udp,icmp
    -k,--key              <string>        password to gen symetric key,default:"secret key"
    --cipher-mode         <string>        avaliable values:aes128cbc(default),xor,none
    --auth-mode           <string>        avaliable values:hmac_sha1,md5(default),crc32,simple,none
    -a,--auto-rule                        auto add (and delete) iptables rule
    -g,--gen-rule                         generate iptables rule then exit,so that you can copy and
                                          add it manually.overrides -a
    --disable-anti-replay                 disable anti-replay,not suggested
client options:
    --source-ip           <ip>            force source-ip for raw socket
    --source-port         <port>          force source-port for raw socket,tcp/udp only
                                          this option disables port changing while re-connecting
other options:
    --conf-file           <string>        read options from a configuration file instead of command line.
                                          check example.conf in repo for format
    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program,
                                          check readme.md in repository for supported commands.
    --log-level           <number>        0:never    1:fatal   2:error   3:warn
                                          4:info (default)     5:debug   6:trace
    --log-position                        enable file name,function name,line number in log
    --disable-color                       disable log color
    --disable-bpf                         disable the kernel space filter,most time its not necessary
                                          unless you suspect there is a bug
    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024
    --force-sock-buf                      bypass system limitation while setting sock-buf
    --seq-mode            <number>        seq increase mode for faketcp:
                                          0:static header,do not increase seq and ack_seq
                                          1:increase seq for every packet,simply ack last seq
                                          2:increase seq randomly, about every 3 packets,simply ack last seq
                                          3:simulate an almost real seq/ack procedure(default)
                                          4:similiar to 3,but do not consider TCP Option Window_Scale,
                                          maybe useful when firewall doesnt support TCP Option
    --lower-level         <string>        send packets at OSI level 2, format:'if_name#dest_mac_adress'
                                          ie:'eth0#00:23:45:67:89:b9'.or try '--lower-level auto' to obtain
                                          the parameter automatically,specify it manually if 'auto' failed
    --gen-add                             generate iptables rule and add it permanently,then exit.overrides -g
    --keep-rule                           monitor iptables and auto re-add if necessary.implys -a
    --clear                               clear any iptables rules added by this program.overrides everything
    -h,--help                             print this help message

```

### Iptables rules,`-a` and `-g`
### IPTables 规则，选项 `-a` 和 `-g`
This program sends packets via raw socket. In FakeTCP mode, Linux kernel TCP packet processing has to be blocked by a iptables rule on both sides, otherwise the kernel will automatically send RST for an unrecongized TCP packet and you will sustain from stability / peformance problems. You can use `-a` option to let the program automatically add / delete iptables rule on start / exit. You can also use the `-g` option to generate iptables rule and add it manually.

udp2raw 用 raw socket 发送数据包。在 假TCP 封包模式，Linux 内核的 TCP 封包处理必须在双向 IPTables 启用的情况下进行，否则 Linux 内核将会自动重置未识别的 TCP 封包，此时就会遇到稳定性/性能问题。可以使用 `-a` 选项让 udp2raw 在启动或停止时自动添加或删除 iptables 规则。你也可以使用 `-g` 选项来生成 iptables 规则并手动添加。

### `--cipher-mode` and `--auth-mode`
### 选项 `--cipher-mode` 和`--auth-mode`
It is suggested to use `aes128cbc` + `hmac_sha1` to obtain maximum security. If you want to run the program on a router, you can try `xor` + `simple`, which can fool packet inspection by firewalls the most of time, but it cannot protect you from serious attacks. Mode none is only for debugging purpose. It is not recommended to set the cipher-mode or auth-mode to none.

建议使用 `aes128cbc` + `hmac_sha1` 以获得最佳安全性。如果你想在你的路由器上使用 udp2raw ，你可以尝试大多数情况下可以骗过防火墙的封包检查，但无法防止严重攻击的 `xor` + `simple` 。仅在调试模式下将这两个选项设为 `none` ，这是不建议的。

### `--seq-mode`

### 选项 `--seq-mode`

The FakeTCP mode does not behave 100% like a real tcp connection. ISPs may be able to distinguish the simulated tcp traffic from the real TCP traffic (though it's costly). seq-mode can help you change the seq increase behavior slightly. If you experience connection problems, try to change the value.

假TCP 封包模式并不 100% 表现得像真 TCP 连接。ISP可能有能力将 假TCP 与 真TCP 连接区分开，尽管开销很大。 `seq-mode` 可以给 seq 增加行为做略微修改。如果你遇到了问题，尝试修改这个选项。

### `--lower-level`
`--lower-level` allows you to send packet at OSI level 2(link level),so that you can bypass any local iptables rules. If you have a complicated iptables rules which conflicts with udp2raw and you cant(or too lazy to) edit the iptables rules,`--lower-level` can be very useful. Try `--lower-level auto` to auto detect the parameters,you can specify it manually if `auto` fails.

Manual format `if_name#dest_mac_adress`,ie:`eth0#00:23:45:67:89:b9`.

### `--keep-rule`
Monitor iptables and auto re-add iptables rules(for blocking kernel tcp processing) if necessary.Especially useful when iptables rules may be cleared by other programs(for example,if you are using openwrt,everytime you changed and commited a setting,iptables rule may be cleared and re-constructed).

### `--conf-file`

You can also load options from a configuration file in order to keep secrets away from `ps` command.

For example, rewrite the options for the above `server` example (in Getting Started section) into configuration file:

`server.conf`

```
-s
# You can add comments like this
# Comments MUST occupy an entire line
# Or they will not work as expected
# Listen address
-l 0.0.0.0:4096
# Remote address
-r 127.0.0.1:7777
-a
-k passwd
--raw-mode faketcp
```

Pay attention to the `-k` parameter: In command line mode the quotes around the password will be removed by shell. In configuration files we do not remove quotes.

Then start the server with

```bash
./udp2raw_amd64 --conf-file server.conf
```

### `--fifo`
Use a fifo(named pipe) for sending commands to the running program. For example `--fifo fifo.file`.

At client side,you can use `echo reconnect >fifo.file` to force client to reconnect.Currently no command has been implemented for server.

# Peformance Test
#### Test method:
iperf3 TCP via OpenVPN + udp2raw
(iperf3 UDP mode is not used because of a bug mentioned in this issue: https://github.com/esnet/iperf/issues/296 . Instead, we package the TCP traffic into UDP by OpenVPN to test the performance. Read [Application](https://github.com/wangyu-/udp2raw-tunnel#application) for details.

#### iperf3 command:
```
iperf3 -c 10.222.2.1 -P40
iperf3 -c 10.222.2.1 -P40 -R
```
#### Environments
* **Client** Vultr $2.5/monthly plan (single core 2.4GHz cpu, 512MB RAM, Tokyo, Japan)
* **Server** BandwagonHost $3.99/annually plan (single core 2.0GHz cpu, 128MB RAM, Los Angeles, USA)

### Test1
raw_mode: faketcp  cipher_mode: xor  auth_mode: simple

![image4](images/image4.PNG)

(reverse speed was simliar and not uploaded)

### Test2
raw_mode: faketcp  cipher_mode: aes128cbc  auth_mode: md5

![image5](images/image5.PNG)

(reverse speed was simliar and not uploaded)

# wiki

Check wiki for more info:

https://github.com/wangyu-/udp2raw-tunnel/wiki
