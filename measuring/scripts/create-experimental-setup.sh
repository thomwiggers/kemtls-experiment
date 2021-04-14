#!/bin/bash

set -e

ROOT=$(dirname $0)/../../
cd $ROOT

export KEX_ALG="${1:-Kyber512}"
export LEAF_ALG="${2:-Dilithium2}"
export INT_SIGALG="${3:-Dilithium2}"
export ROOT_SIGALG="${4:-Dilithium2}"
export CLIENT_ALG="${5}"
export CLIENT_CA_ALG="${6}"


tag=${KEX_ALG,,}-${LEAF_ALG,,}-${INT_SIGALG,,}-${ROOT_SIGALG,,}

extra_args=
if [ "$CLIENT_ALG" != "" ]; then
    tag=${tag}-clauth-${CLIENT_ALG,,}-${CLIENT_CA_ALG,,}
    extra_args="--build-arg CLIENT_ALG=$CLIENT_ALG --build-arg CLIENT_CA_ALG=$CLIENT_CA_ALG"
fi

docker build \
    --build-arg ROOT_SIGALG=$ROOT_SIGALG \
    --build-arg INT_SIGALG=$INT_SIGALG \
    --build-arg LEAF_ALG=$LEAF_ALG \
    --build-arg KEX_ALG=$KEX_ALG \
    $extra_args \
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