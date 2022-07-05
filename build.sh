set -em

zig build

sudo setcap cap_net_admin=eip zig-out/bin/netstack

./zig-out/bin/netstack &
pid=$!
trap 'kill $(jobs -p)' EXIT

sudo ip link set up dev tun0
sudo ip route add dev tun0 10.0.0.0/24
sudo ip address add 10.0.0.1/24 dev tun0

fg %1
