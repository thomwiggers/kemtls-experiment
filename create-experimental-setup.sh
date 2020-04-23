#!/bin/bash

ROOT=$(dirname $0)
cd $ROOT

export ROOT_SIGALG="${1:-RainbowIaCyclic}"
export INT_SIGALG="${2:-Falcon512}"
export KEX_ALG="${3:-kyber512}"


docker build \
    --build-arg ROOT_SIGALG=$ROOT_SIGALG \
    --build-arg INT_SIGALG=$INT_SIGALG \
    --build-arg KEX_ALG=$KEX_ALG \
    --tag pqtls-builder:$KEX_ALG .

volumename=$PWD/measuring/bin/$KEX_ALG-${INT_SIGALG}-${ROOT_SIGALG}
echo $volumename
rm -rf $volumename
mkdir -p $volumename

docker run --rm \
    --user $(id -u):$(id -g) \
    --volume $volumename:/output \
    --workdir /output   \
    pqtls-builder:$KEX_ALG \
    bash -c "cp /usr/local/bin/*tlsserver . &&
             cp /usr/local/bin/*tlsclient . &&
             cp /certs/* ."

for f in $volumename/$KEX_ALG.*; do
    f=$(basename $f)
    mv $volumename/$f $volumename/${f/$KEX_ALG/kem}
done
