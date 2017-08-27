# How to run udp2raw on a rooted android device(arm cpu)

There is currently no GUI for udp2raw on android.Make sure you have installed Terminal to run it.Your device has to be rooted,otherwise you cant use raw socket.

Download udp2raw_arm from https://github.com/wangyu-/udp2raw-tunnel/releases.

Copy udp2raw_arm to any dir of your **internal storage** .Copying it to **SD card wont work**.

# Steps
1.  run udp2raw_arm  as usual, except you must change the -a option to -g
```
./udp2raw_arm -c -r 44.55.66.77:9966 -l 0.0.0.0:4000 -k1234 --cipher xor -g
```

2. find the generated iptables rule from udp2raw's output,add it manually by running:
```
iptables -I INPUT -s 44.55.66.77/32 -p tcp -m tcp --sport 9966 -j DROP
```

3. run udp2raw_ram without -g command

```
./udp2raw_arm -c -r 44.55.66.77:9966 -l 0.0.0.0:4000 -k1234 --cipher xor 
```

# ScreenShot 
zoom-in if not large enough

![](/images/android.png)
