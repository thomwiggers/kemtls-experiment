#!/bin/bash

pushd rustls
python generate_schemes.py
git add rustls/src/generated
popd
pushd webpki/src
python generate_schemes.py
git add data generated
popd
