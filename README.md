# Zig Netstack


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
