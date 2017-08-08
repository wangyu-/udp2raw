# Udp2raw-tunnel
![image0](images/image0.PNG)

An Encrpyted,Anti-Replay,Multiplexed Udp Tunnel,tunnels udp traffic through raw socket

[简体中文](/doc/README.zh-cn.md)
### Send/Recv Udp Packet as Raw Packet with TCP header,ICMP header
Which can help you bypass udp blocking or udp QOS or just poorly supported udp NAT behavior by some ISP. Raw packet with UDP header is also supported,in this way you can just make use of the encrpyting and anti-replay feature.
### Encrpytion and Anti-Replay
encrypt your traffic with aes128cbc,protects data integrity by md5 or crc32,protect replay attack with an anti-replay window smiliar to ipsec/openvpn.
### Simulated TCP Handshake
simulated 3-way handshake,simluated seq ack_seq. Simluated tcp options:MSS,sackOk,TS,TS_ack,wscale. Provides real-time delivery ,no tcp over tcp problem when using openvpn.
### Connnection Failure Dectection & Recover
Conection failure detection by hearbeat. After hearbeat timeouts,client will auto change port and re-connect.if re-connection is successful,the previous connection will be recovered,and all existed udp conversations will stay vaild.
### Other Features
Multiplexing ,one client supports multi udp connections,all of those traffic will share one raw connection

Multiple Clients Support,one server supports multiple clients.

NAT Supported,all 3 modes work in NAT environment 

OpenVZ Supported,tested on bandwagonhost

Openwrt Supported,no dependence package,easy to compile,ar71xx binary included in release.
### Key Words
bypass udp qos,bypass udp blocking,openvpn tcp over tcp problem,openvpn over icmp,udp to icmp tunnel,udp to tcp tunnel,udp via icmp,udp via tcp
# Getting Started
### Prerequisites
linux host,root access.  if you want to use it on window,you can use VMware in bridged mode.
### Installing
download binary release from https://github.com/wangyu-/udp2raw-tunnel/releases
### Running 
assume your udp is blocked or being QOS-ed or just poorly supported.assume your server ip is 44.55.66.77, you have a service listening on udp port 7777.
```
run at client side:
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -a -k "passwd" --raw-mode faketcp

run at server side:
./udp2raw_amd64 -s -l0.0.0.0:4096 -r 127.0.0.1:7777  -a -k "passwd" --raw-mode faketcp

```
Now,your client and server established a tunnel thorough tcp port 4096. Connecting to udp port 3333 at client side  is equivalent with connecting to port 7777 at server side. No udp traffic will be exposed to outside.
# Advanced Topic
### Usage
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
### iptables rule
this programs sends packet via raw socket.In faketcp mode,Linux Kernel TCP packet processing has to be blocked by a iptables rule on both sides,otherwise Kernel will automatically send RST for unrecongized TCP packet and you will sustain from stability/peformance problem.You can use -a option to let the program automatically add/del iptables rule on start/exit.You can also use the -g option to generate iptables rule and add it manually.
### cipher-mode and auth-mode 
Its suggested to use aes128cbc + md5 to obtain maxmized security.If you want to run the program on a router,you can try xor+simple,it can fool Packet Inspection by firewalls most time, but it cant protect you from serious attackers. Mode none is only for debug,its not suggest to set cipher-mode or auth-mode to none.
### seq-mode
the faketcp mode doest not behave 100% like a real tcp connection.ISP may be able to distinguish the simulated tcp traffic from real tcp traffic(though its costly). seq-mode can help you changed the seq increase behavior a bit. If you experienced problems,try to change the value. 
# Peformance Test
#### test method:
iperf3 tcp via openvpn + udp2raw 
(iperf3 udp mode is not used bc of bug mentioned in this issue: https://github.com/esnet/iperf/issues/296 ,instead,we turn iperf3 's tcp traffic into udp by using openvpn,to test udp2raw 's peformance. Read [Application](https://github.com/wangyu-/udp2raw-tunnel#application) for detail )
#### iperf3 command: 
```
iperf3 -c 10.222.2.1 -P40 
iperf3 -c 10.222.2.1 -P40 -R
```
#### client host
vultr $2.5/monthly plan(single core 2.4ghz cpu,512m ram,location:Tokyo,Japan),
#### server host
bandwagonhost $3.99/annually(single core 2.0ghz cpu,128m ram,location:Los Angeles,USA)
### Test1
raw_mode: faketcp  cipher_mode: xor  auth_mode: simple

![image4](images/image4.PNG)

(reverse speed is simliar and not uploaded)

### Test2
raw_mode: faketcp  cipher_mode: aes128cbc  auth_mode: md5

![image5](images/image5.PNG)

(reverse speed is simliar and not uploaded)

# Application
### tunneling any traffic via raw traffic by using udp2raw +openvpn
![image_vpn](images/openvpn.PNG)
1. bypasses UDP block/UDP QOS

2. no TCP ovr tcp problem (tcp over tcp problem http://sites.inka.de/bigred/devel/tcp-tcp.html ,https://community.openvpn.net/openvpn/ticket/2 )

3. openvpn over icmp also becomes a choice

more details at [openvpn+udp2raw_guide](/doc/openvpn_guide.md)
### tunneling kcptun
make kcptun support tcp mode.
(kcptun, https://github.com/xtaci/kcptun)

### tunneling finalspeed
finalspeed 's tcp mode doesnt work on openvz VPS.you can use finalspeed 's udp mode,and tunnel udp through tcp with this tunnel.

# Related work
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

