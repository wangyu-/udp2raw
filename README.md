# Udp2raw-tunnel
An Encrpyted,Anti-Replay,Multiplexed Udp Tunnel,tunnels udp traffic through raw socket,send/recv udp packet as raw packet with fake tcp/icmp header. Which can help you bypass udp blocking or udp qos. It also supports sending raw packet as udp packet,in this way you can just may use of the encrpyting and anti-replay feature.

Nat supported in 3 the 3 modes.

In tcp mode simulated 3-way hand-shake,simluated seq ack_seq are implemented. those tcp options are implemented:MSS,sackOk,TS,TS_ack,wscale  


## Getting Started

### Prerequisites
linux host with root access

### Installing
download binary release from https://github.com/wangyu-/udp2raw-tunnel/releases

### Running 
```
client:
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -a

server(assume ip is 44.55.66.77):
./udp2raw -s -l44.55.66.77:4096 -r 127.0.0.1:7777  -a

```

