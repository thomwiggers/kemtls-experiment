#!/bin/bash

set -e

ROOT=$(dirname $0)/../../
cd $ROOT

export KEX_ALG="${1:-Kyber512}"
export LEAF_SIGALG="${2:-Dilithium2}"
export INT_SIGALG="${3:-Dilithium2}"
export ROOT_SIGALG="${4:-Dilithium2}"


docker build \
    --build-arg ROOT_SIGALG=$ROOT_SIGALG \
    --build-arg INT_SIGALG=$INT_SIGALG \
    --build-arg LEAF_SIGALG=$LEAF_SIGALG \
    --build-arg KEX_ALG=$KEX_ALG \
    --tag pqtls-builder:$KEX_ALG .

volumename=$PWD/measuring/bin/${KEX_ALG,,}-${LEAF_SIGALG,,}-${INT_SIGALG,,}-${ROOT_SIGALG,,}
echo $volumename
rm -rf $volumename
mkdir -p $volumename

docker run --rm \
    --user $(id -u):$(id -g) \
    --volume $volumename:/output \
    --workdir /output   \
    pqtls-builder:$KEX_ALG \
    bash -c "cp /usr/local/bin/tlsserver . &&
             cp /usr/local/bin/tlsclient . &&
             cp /certs/* ."