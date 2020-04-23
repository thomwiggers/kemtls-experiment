#!/bin/bash

set -e

if [ "$(whoami)" != "root" ]; then
    echo "Please run me as root"
    exit 1;
fi

# Start server
docker run --rm --detach --interactive --tty --name server pqtls:latest \
    tlsserver --cert kyber512.chain.crt --key kyber512.key --verbose http

LATENCIES="50 100"

# figure out interface
INTERFACE=$(./dockerveth.sh | cut -f2)
SERVERIP=$(docker container inspect server | jq -r ".[0].NetworkSettings.IPAddress")

# Output directory
DIR=measurements/data

quit() {
    echo "Stopping"
    echo "Terminating server container"
    docker kill server
    exit $1
}

mkdir -p "${DIR}"

echo "Name of the server interface: $INTERFACE"
echo "IP address of the server: $SERVERIP"

for lat in $LATENCIES; do
    echo "Disable optimisations that dent realism as in https://github.com/xvzcf/pq-tls-benchmark/blob/master/emulation-exp/code/setup_ns.sh"
    ethtool -K $INTERFACE gso off gro off tso off

    echo "Setting up measurements for $lat ms"
    tc qdisc add dev $INTERFACE root netem delay ${lat}ms

    echo "Setting up monitoring"
    tcpdump --time-stamp-precision nano -i $INTERFACE -w ${DIR}/measurement-$(date +%s)-${lat}ms.pcap &
    sleep 3

    echo "Run measurements"
    docker run --rm --interactive --tty --name client --env SERVERIP=$SERVERIP opensslkem

    echo "Stopping monitoring"
    killall -INT tcpdump || quit 1
    sleep 3

    echo "Checking if tcpdump quit."
    pgrep tcpdump && quit 1 || true

    echo "Removing latency"
    tc qdisc del dev $INTERFACE root netem delay ${lat}ms
    sleep 2
done

echo "Done!"

quit 0

