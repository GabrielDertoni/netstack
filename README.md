# Zig Netstack

## Running

```sh
# This will most likely ask for sudo since it needs to configure the TUN device.
zig build run
```

## Arping

For some reason, even though there is a routing table entry for the network `10.0.0.0`, arping won't be able to figure out automatically where to route the arp request. Therefore, we need to manually set which interface and source ip to use. If you give the interface an ip address, then `arping` can figure it out. It will use the interface ip address as the source.

```sh
# May require sudo
arping -i tun0 -S 0.0.0.0 10.0.0.2
#         ^^^^    ^^^^^^^~~~ source ip to use
#       interface
```

## Pinging

Pinging the interface is a little easier. It will look up the route table and figure out that, in order to get to the 10.0.0.2 address, it needs to talk to interface `tun0`. Then, it will send and ARP request to that interface (if needed) in order to get the MAC address for the `10.0.0.2` ip. Finally, it can send the ICMP echo packet directly to the MAC address acquired.

```sh
ping 10.0.0.2
```

## Configuring iptables

In order to reach outside the interfaces' network, the `iptables` must be configured to route all packets coming from the `tun0` interface to go through your output interface and vice versa.

```sh
# In my case the interface connected to the internet is eth0, you need to use yours.
# Check `ip addr` to see which you should use here.
OUT_INTERFACE=eth0

sysctl -w net.ipv4.ip_forward=1
iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
iptables -t nat -I POSTROUTING --out-interface $OUT_INTERFACE -j MASQUERADE

iptables -I FORWARD --in-interface $OUT_INTERFACE --out-interface tap0 -j ACCEPT
iptables -I FORWARD --in-interface tap0 --out-interface $OUT_INTERFACE -j ACCEPT
```

## Ping from the interface

```sh
zig build run -- --ping 8.8.8.8
```

## TODOs

- [ ] Implement a custom event loop for handling async tasks.
- [ ] Implement UDP send.
- [ ] Implement TCP.
- [ ] Implement as daemon and interact with other processes through IPC.
