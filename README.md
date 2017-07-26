# udp2raw-tunnel
udp2raw tunnel  (udp to tcp with fake tcp header)

#usage

client:
-A INPUT -s 44.55.66.77/32 -p tcp -m tcp --sport 9999 -j DROP

./raw -l 127.0.0.1:6666 -r44.55.66.77:9999 -c --source-ip 192.168.1.100

server:
-A INPUT -p tcp -m tcp --dport 9999 -j DROP

./raw -l44.55.66.77:9999 -r 127.0.0.1:5555  -s
