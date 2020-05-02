#!/bin/bash

set -e

echo "Make sure to setup the namespaces beforehand."
echo "Run ./scripts/setup_ns.sh"

echo "This will remove the current experiment data!"
read -p "Are you sure? " -n 1 -r
echo    # (optional) move to a new line

if [[ $REPLY =~ ^[Nn]$ ]]
then
    exit
fi

rm -rf data
if ! [ -d bin ]; then
    sudo ./scripts/create-binaries-and-certs.sh
else
    echo "Delete bin folder to recreate stuff"
fi

sudo killall -9 kemtlsserver  || true
sudo killall -9 pqtlsserver   || true

ntfy done sudo python3 scripts/experiment.py
