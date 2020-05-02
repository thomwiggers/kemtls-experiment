#!/bin/sh

sudo ip netns exec srv_ns ip route change 10.99.0.0/24 via 10.99.0.1 dev srv_ve initcwnd $1
sudo ip netns exec cli_ns ip route change 10.99.0.0/24 via 10.99.0.2 dev cli_ve initcwnd $1
