# systemd service file
```
[Unit]
Description=UDP2RAW service
After=network-online.service

[Service]
User=nobody
Type=simple
PermissionsStartOnly=true
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
ExecStartPre=/sbin/iptables -I INPUT -s SERVER_IP -p tcp --sport SERVER_PORT -j DROP
ExecStart=/usr/bin/udp2raw -c -l127.0.0.1:LOCAL_PORT -rSERVER_IP:SERVER_PORT -k PASSWORD --raw-mode faketcp
ExecStopPost=/sbin/iptables -D INPUT -s SERVER_IP -p tcp --sport SERVER_PORT -j DROP
Restart=always
RestartSec=30
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
```

Please replace `SERVER_IP`, `SERVER_PORT` and `LOCAL_PORT` with your own parameters and replace the pathes to `iptables` and `udp2raw` according to your own system configuration.

The above unit will only execute the `iptables` commands as root, and will execute the main `udp2raw` command as `nobody`, with `CapabilityBoundingSet` that grants necessary permissions.

You may also need to run `setcap cap_net_raw,cap_net_admin+ep udp2raw` on the `udp2raw` binary
