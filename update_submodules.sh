#!/bin/zsh

pushd mk-cert
git submodule update
pushd signutil
cargo update
git add Cargo.lock
popd
pushd kemutil
cargo update
git add Cargo.lock
popd

git commit -m "Update Cargo lockfiles"
git push

popd
git add mk-cert

pushd rustls
cargo update
popd

pushd webpki
cargo update
popd
