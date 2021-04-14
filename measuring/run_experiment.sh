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
if [ -d bin ]; then
    echo "Delete bin folder to recreate stuff"
fi

sudo killall -9 tlsserver  || true

ntfy done sudo -E python3.9 -u scripts/experiment.py $@
