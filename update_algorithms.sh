#!/bin/bash
set -e

pushd mk-cert/kemutil
cargo update
popd
pushd mk-cert/signutil
cargo update
popd

pushd webpki/src
python generate_schemes.py
git add data generated
popd

pushd webpki
cargo update
cargo check
popd

pushd rustls
python generate_schemes.py
git add rustls/src/generated
cargo update
popd

pushd rustls/test-ca

for dir in kyber dilithium; do
    pushd $dir
    bash cp_from_mkcert.sh
    git add .
    popd
done

popd
