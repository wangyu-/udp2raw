# udp2raw+openvpn config guide
![image_vpn](/images/openvpn.PNG)

![image4](/images/image4.PNG)
# udp2raw command
#### run at server side
```
./udp2raw_amd64 -s -l0.0.0.0:8855 -r 127.0.0.1:7777 -k "passwd" --raw-mode faketcp -a
```
#### run at client side
assume server ip is 45.66.77.88
```
./udp2raw_amd64 -s -l0.0.0.0:3333 -r 45.66.77.88:8855 -k "passwd" --raw-mode faketcp -a
```


# openvpn config

#### client side config
```
client
dev tun100
proto udp

remote 127.0.0.1 3333
resolv-retry infinite 
nobind 
persist-key 
persist-tun  

ca /root/add-on/openvpn/ca.crt
cert /root/add-on/openvpn/client.crt
key /root/add-on/openvpn/client.key

keepalive 3 20
verb 3
mute 20

comp-lzo no
cipher none      ##### disable openvpn 's cipher and auth for maxmized peformance. 
auth none        ##### you can enable openvpn's cipher and auth,if you dont care about peformance,or you dont trust udp2raw 's encryption

fragment 1200       ##### very important    you can turn it up a bit. but,the lower the safer
mssfix 1200         ##### very important

sndbuf 2000000      ##### important
rcvbuf 2000000      ##### important
txqueuelen 4000     ##### suggested
```


#### server side config
```
local 0.0.0.0
port 7777 
proto udp
dev tun 

ca /etc/openvpn/easy-rsa/2.0/keys/ca.crt
cert /etc/openvpn/easy-rsa/2.0/keys/server.crt
key /etc/openvpn/easy-rsa/2.0/keys/server.key
dh /etc/openvpn/easy-rsa/2.0/keys/dh1024.pem

server 10.222.2.0 255.255.255.0 
ifconfig 10.222.2.1 10.222.2.6

client-to-client
duplicate-cn 
keepalive 10 60 

max-clients 50

persist-key
persist-tun

status /etc/openvpn/openvpn-status.log

verb 3
mute 20  

comp-lzo no
cipher none      ##### disable openvpn 's cipher and auth for maxmized peformance. 
auth none        ##### you can enable openvpn's cipher and auth,if you dont care about peformance,or you dont trust udp2raw 's encryption

fragment 1200       ##### very important    you can turn it up a bit. but,the lower the safer
mssfix 1200         ##### very important

sndbuf 2000000      ##### important
rcvbuf 2000000      ##### important
txqueuelen 4000     ##### suggested
```
