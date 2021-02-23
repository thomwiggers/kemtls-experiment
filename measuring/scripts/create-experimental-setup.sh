#!/bin/bash

set -e

ROOT=$(dirname $0)/../../
cd $ROOT

export KEX_ALG="${1:-Kyber512}"
export LEAF_ALG="${2:-Dilithium2}"
export INT_SIGALG="${3:-Dilithium2}"
export ROOT_SIGALG="${4:-Dilithium2}"

tag=${KEX_ALG,,}-${LEAF_ALG,,}-${INT_SIGALG,,}-${ROOT_SIGALG,,}

docker build \
    --build-arg ROOT_SIGALG=$ROOT_SIGALG \
    --build-arg INT_SIGALG=$INT_SIGALG \
    --build-arg LEAF_ALG=$LEAF_ALG \
    --build-arg KEX_ALG=$KEX_ALG \
    --tag pqtls-builder:$tag .

volumename=$PWD/measuring/bin/$tag
echo $volumename
rm -rf $volumename
mkdir -p $volumename

docker run --rm \
    --user $(id -u):$(id -g) \
    --volume $volumename:/output \
    --workdir /output   \
    pqtls-builder:$tag \
    bash -c "cp /usr/local/bin/tlsserver . &&
             cp /usr/local/bin/tlsclient . &&
             cp /certs/* ."

if [ "$SUDO_USER" != "" ]; then
    chown -R $SUDO_USER:$SUDO_GID .
fi