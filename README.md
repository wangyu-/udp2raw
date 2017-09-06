# Udp2raw-tunnel
![image0](images/image0.PNG)

A Tunnel which turns UDP Traffic into Encrypted FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment). It can defend Replay-Attack and supports Multiplexing. It also acts as a Connection Stabilizer.

It can tunnel any traffic when used together with a UDP-based VPN(such as OpenVPN).Check [this link](https://github.com/wangyu-/udp2raw-tunnel#tunneling-any-traffic-via-raw-traffic-by-using-udp2raw-openvpn) for more info.

[简体中文](/doc/README.zh-cn.md)
# Frequently Asked Questions
### Q: What is the advantage of using udp2raw FakeTCP mode,why not use a TCP-based VPN(such as OpenVPN TCP mode)?
Answer: **TCP doesnt allow real-time/out-of-order delivery**. **If you use OpenVPN TCP mode to turn UDP traffic into TCP,there will be latency issue**:the loss of a single packet blocks all following packet until re-transmission is done. This will cause unacceptable delay for gaming and voice chatting.

**TCP also has re-transmission and congestion control which cant be disabled.** UDP programs usualy want to control packet sending rate by themselves. If you use OpenVPN TCP mode this cant be done because of the congestion control of underlying TCP protocol. Further more,with the re-transmission of underlying TCP,**if you send too many udp packets via an OpenVPN TCP connection,the connection will become completely unusable for a while**(It will eventually recover as most of the re-transmission is done,but it wont be very soon).

Those issues exist for almost all TCP-based VPNs.

For udp2raw there is no underlying TCP protocol,udp2raw just add TCP headers to UDP packets directly by using raw socket. It supports real-time/out-of-order delivery,there is no re-transmission and congestion control. **Udp2raw doesnt have all above issues**.

### Q: Is udp2raw designed for replacing VPN?
Answer: No. Udp2raw is designed for bypassing UDP restrictions. It doesnt have all of the features a VPN has(such as transparently redirect all traffic).

Instead of replacing VPN,udp2raw can be used with any UDP-based VPN together to grant UDP-based VPN the ablity of bypassing UDP restrictions,while not having the performance issue involved by a TCP-based VPN. Check [this link](https://github.com/wangyu-/udp2raw-tunnel#tunneling-any-traffic-via-raw-traffic-by-using-udp2raw-openvpn) for more info.

# Support Platforms
Linux host (including desktop Linux,Android phone/tablet,OpenWRT router,or Raspberry PI) with root access.

For Winodws/MacOS,the 4.4mb virtual image with udp2raw pre-installed has been released,you can load it with Vmware/VirtualBox.The virtual image has been set to auto obtain ip,udp2raw can be run imidiately after boot finished(make sure network mode of virtual machine has been set to bridged)(only udp2raw has to be run under virtual machine,all other programs runs under Windows/MacOS as usual).


# Features 
### Send/Receive UDP Packets with ICMP/FakeTCP/UDP headers
ICMP/FakeTCP headers help you bypass UDP blocking, UDP QOS or improper UDP NAT behavior on some ISPs. In ICMP header mode,udp2raw works like an ICMP tunnel. 

UDP headers are also supported. In UDP header mode, it behaves just like a normal UDP tunnel, and you can just make use of the other features (such as encrytion, anti-replay, or connection stalization).

### Simulated TCP with Real-time/Out-of-Order Delivery
In FakeTCP header mode,udp2raw simulates 3-way handshake while establishing a connection,simulates seq and ack_seq while data transferring. It also simulates following TCP options: `MSS`, `sackOk`, `TS`, `TS_ack`, `wscale`.Firewalls will regard FakeTCP as a TCP connection, but its essentially UDP: it supports real-time/out-of-order delivery(just as normal UDP does), no congrestion control or re-transmission. So there wont be any TCP over TCP problem when using OpenVPN.

### Encrpytion, Anti-Replay
* Encrypt your traffic with AES-128-CBC.
* Protect data integrity by MD5 or CRC32.
* Defense replay attack with an anti-replay window, smiliar to IPSec and OpenVPN. 

### Failure Dectection & Stablization (Connection Recovery)
Conection failures are detected by heartbeats. If timed-out, client will automatically change port number and reconnect. If reconnection is successful, the previous connection will be recovered, and all existing UDP conversations will stay vaild. 

For example, if you use udp2raw + OpenVPN, OpenVPN won't lose connection after any reconnect, **even if network cable is re-plugged or WiFi access point is changed**.

### Other Features
* **Multiplexing** One client can handle multiple UDP connections, all of which share the same raw connection.

* **Multiple Clients** One server can have multiple clients.

* **NAT Support** All of the 3 modes work in NAT environments.

* **OpenVZ Support** Tested on BandwagonHost VPS.

* **Easy to Build** No dependencies.To cross-compile udp2raw,all you need to do is just to download a toolchain,modify makefile to point at the toolchain,run `make cross` then everything is done.(Note:Pre-compiled binaries for Desktop,RaspberryPi,Android,some Openwrt Routers are already included in [Releases](https://github.com/wangyu-/udp2raw-tunnel/releases))

### Keywords
`Bypass UDP QoS` `Bypass UDP Blocking` `Bypass OpenVPN TCP over TCP problem` `OpenVPN over ICMP` `UDP to ICMP tunnel` `UDP to TCP tunnel` `UDP over ICMP` `UDP over TCP`

# Getting Started
### Installing
Download binary release from https://github.com/wangyu-/udp2raw-tunnel/releases

### Running 
Assume your UDP is blocked or being QOS-ed or just poorly supported. Assume your server ip is 44.55.66.77, you have a service listening on udp port 7777.

```bash
# Run at server side:
./udp2raw_amd64 -s -l0.0.0.0:4096 -r 127.0.0.1:7777  -a -k "passwd" --raw-mode faketcp

# Run at client side
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -a -k "passwd" --raw-mode faketcp
```
###### Server Output:
![](images/output_server.PNG)
###### Client Output:
![](images/output_client.PNG)

Now,an encrypted raw tunnel has been established between client and server through TCP port 4096. Connecting to UDP port 3333 at the client side is equivalent to connecting to port 7777 at the server side. No UDP traffic will be exposed.

### Note
To run on Android, check [Android_Guide](/doc/android_guide.md)

If you have connection problems.Take a look at `--seq-mode` option.

You can run udp2raw with a non-root account(for better security).Take a look at [#26](https://github.com/wangyu-/udp2raw-tunnel/issues/26) for more info. 

# Advanced Topic
### Usage
```
udp2raw-tunnel
version: Aug 26 2017 08:30:48
repository: https://github.com/wangyu-/udp2raw-tunnel

usage:
    run as client : ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]
    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]

common options,these options must be same on both side:
    --raw-mode            <string>        avaliable values:faketcp(default),udp,icmp
    -k,--key              <string>        password to gen symetric key,default:"secret key"
    --cipher-mode         <string>        avaliable values:aes128cbc(default),xor,none
    --auth-mode           <string>        avaliable values:md5(default),crc32,simple,none
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
    --log-level           <number>        0:never    1:fatal   2:error   3:warn 
                                          4:info (default)     5:debug   6:trace
    --log-position                        enable file name,function name,line number in log
    --disable-color                       disable log color
    --disable-bpf                         disable the kernel space filter,most time its not necessary
                                          unless you suspect there is a bug
    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024
    --seqmode             <number>        seq increase mode for faketcp:
                                          0:dont increase
                                          1:increase every packet(default)
                                          2:increase randomly, about every 3 packets
    --lower-level         <string>        send packets at OSI level 2, format:'if_name#dest_mac_adress'
                                          ie:'eth0#00:23:45:67:89:b9'.or try '--lower-level auto' to obtain
                                          the parameter automatically,specify it manually if 'auto' failed
    --gen-add                             generate iptables rule and add it permanently,then exit.overrides -g
    --keep-rule                           monitor iptables and auto re-add if necessary.implys -a
    --clear                               clear any iptables rules added by this program.overrides everything
    -h,--help                             print this help message

```

### Iptables rules,`-a` and `-g`
This program sends packets via raw socket. In FakeTCP mode, Linux kernel TCP packet processing has to be blocked by a iptables rule on both sides, otherwise the kernel will automatically send RST for an unrecongized TCP packet and you will sustain from stability / peformance problems. You can use `-a` option to let the program automatically add / delete iptables rule on start / exit. You can also use the `-g` option to generate iptables rule and add it manually.

### `--cipher-mode` and `--auth-mode` 
It is suggested to use `aes128cbc` + `md5` to obtain maximum security. If you want to run the program on a router, you can try `xor` + `simple`, which can fool packet inspection by firewalls the most of time, but it cannot protect you from serious attacks. Mode none is only for debugging purpose. It is not recommended to set the cipher-mode or auth-mode to none.

### `--seq-mode`
The FakeTCP mode does not behave 100% like a real tcp connection. ISPs may be able to distinguish the simulated tcp traffic from the real TCP traffic (though it's costly). seq-mode can help you change the seq increase behavior slightly. If you experience connection problems, try to change the value. 

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

# Application
## Tunneling any traffic via raw traffic by using udp2raw +openvpn
![image_vpn](images/openvpn.PNG)
1. Bypasses UDP block/UDP QOS

2. No TCP over TCP problem (TCP over TCP problem http://sites.inka.de/bigred/devel/tcp-tcp.html ,https://community.openvpn.net/openvpn/ticket/2 )

3. OpenVpn over ICMP also becomes a choice

4. Supports almost any UDP-based VPN

More details at [openvpn+udp2raw_guide](/doc/openvpn_guide.md)
## Speed-up tcp connection via raw traffic by using udp2raw+kcptun
kcptun is a tcp connection speed-up program,it speeds-up tcp connection by using kcp protocol on-top of udp.by using udp2raw,you can use kcptun while udp is QoSed or blocked.
(kcptun, https://github.com/xtaci/kcptun)

## Speed-up tcp connection via raw traffic by using udp2raw+finalspeed
finalspeed is a tcp connection speed-up program similiar to kcptun,it speeds-up tcp connection by using kcp protocol on-top of udp or tcp.but its tcp mode doesnt support openvz,you can bypass this problem if you use udp2raw+finalspeed together,and icmp mode also becomes avaliable.

# How to build
read [build_guide](/doc/build_guide.md)

# Other
### Easier installation on ArchLinux
```
yaourt -S udp2raw-tunnel # or
pacaur -S udp2raw-tunnel
```

# Related work
### kcptun-raw
udp2raw was inspired by kcptun-raw,which modified kcptun to support tcp mode.

https://github.com/Chion82/kcptun-raw
### relayRawSocket
kcptun-raw was inspired by relayRawSocket. A simple  udp to raw tunnel,wrote in python

https://github.com/linhua55/some_kcptun_tools/tree/master/relayRawSocket
### kcpraw
another project of kcptun with tcp mode

https://github.com/ccsexyz/kcpraw

### icmptunnel
Transparently tunnel your IP traffic through ICMP echo and reply packets.

https://github.com/DhavalKapil/icmptunnel

### Tcp Minion
Tcp Minion is a project which modifid the code of tcp stack in kernel,and implemented real-time out-order udp packet delivery through this modified tcp stack.I failed to find the implementation,but there are some papers avaliable:

https://arxiv.org/abs/1103.0463

http://korz.cs.yale.edu/2009/tng/papers/pfldnet10.pdf

https://pdfs.semanticscholar.org/9e6f/e2306f4385b4eb5416d1fcab16e9361d6ba3.pdf
