#!/bin/bash

if ! [ -f "count-hs-bytes.py" ]; then
    echo "Need to run this from where I exist"
    exit 1
fi

PORT=4443

TMPDIR="$(mktemp -d -t tmp.MESXXXXXXXX)"
OUTFILE=/tmp/sizes.log

if [[ "$(getent hosts servername)" != "127.0.0.1       servername" ]]; then
    echo "You need to probably fix /etc/hosts to set servername to 127.0.0.1";
    exit 1;
fi

export LOGLEVEL=DEBUG

loops=1

rm -rf $OUTFILE

for dir in $@; do
    pushd $dir;
    if [ -f "signing.crt" ]; then
        echo "PQTLS"
        if [[ "$dir" = *"classicmceliece"* ]]; then
            echo "Skipping McEliece"
            popd
            continue
        fi
        killall tlsserver tlsclient 2> /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/pqtls-dump.pcap &
        sharkpid=$!
        sleep 1
        if [[ "$dir" = *"-clauth-"* ]]; then
            ./tlsserver --port $PORT --certs signing.chain.crt --auth client-ca.crt --require-auth --key signing.key http > $TMPDIR/server_pqtls_mut.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile signing-ca.crt --auth-certs client.crt --auth-key client.key --no-tickets --http servername > $TMPDIR/client_pqtls_mut
            echo "Done measuring mutual"
            measurementtype=pqtls-mut
        else
            ./tlsserver --port $PORT --certs signing.chain.crt --key signing.key http > $TMPDIR/server_pqtls.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile signing-ca.crt --no-tickets --http servername > $TMPDIR/client_pqtls.log
            echo "Done measuring unilateral"
            measurementtype=pqtls
        fi
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/pqtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/pqtls-dump.json
        popd > /dev/null
        echo "$dir PQTLS" >> $OUTFILE
        python3 count-hs-bytes.py $measurementtype $TMPDIR/pqtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/pqtls-dump.json /tmp
            mv $TMPDIR/pqtls-dump.pcap /tmp
            exit 1;
        fi
        pushd $dir > /dev/null
    fi
    if [ -f "signing.crt" ]; then
        echo "PQTLS with caching"
        if [[ "$dir" = *"classicmceliece"* ]]; then
            echo "Skipping McEliece"
            popd
            continue
        fi
        killall tlsserver tlsclient 2> /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/pqtls-dump.pcap &
        sharkpid=$!
        sleep 1
        if [[ "$dir" = *"-clauth-"* ]]; then
            ./tlsserver --port $PORT --certs signing.chain.crt --auth client-ca.crt --require-auth --key signing.key http > $TMPDIR/server_pqtls_mut.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile signing-ca.crt --cached-certs signing.chain.crt --auth-certs client.crt --auth-key client.key --no-tickets --http servername > $TMPDIR/client_pqtls_mut
            echo "Done measuring mutual"
            measurementtype=pqtls-mut
        else
            ./tlsserver --port $PORT --certs signing.chain.crt --key signing.key http > $TMPDIR/server_pqtls.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile signing-ca.crt --cached-certs signing.chain.crt --no-tickets --http servername > $TMPDIR/client_pqtls.log
            echo "Done measuring unilateral"
            measurementtype=pqtls
        fi
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/pqtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/pqtls-dump.json
        popd > /dev/null
        echo "$dir PQTLS-CACHED" >> $OUTFILE
        python3 count-hs-bytes.py $measurementtype $TMPDIR/pqtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/pqtls-dump.json /tmp
            mv $TMPDIR/pqtls-dump.pcap /tmp
            exit 1;
        fi
        pushd $dir > /dev/null
    fi
    if [ -f "kem.crt" ]; then
        echo "KEMTLS"
        if [[ "$dir" = *"mceliece"* ]]; then
            echo "Skipping McEliece"
            popd
            continue
        fi
        killall tlsserver tlsclient > /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/kemtls-dump.pcap &
        sharkpid=$!
        sleep 1
        if ! [[ "$dir" = *"clauth"* ]]; then
            ./tlsserver --port $PORT --certs kem.chain.crt --key kem.key http > $TMPDIR/server_kemtls.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile kem-ca.crt --no-tickets --http servername > $TMPDIR/client_kemtls.log
            echo "Done measuring unilateral"
            measurementtype=kemtls
        else
            ./tlsserver --port $PORT --certs kem.chain.crt --require-auth --auth client-ca.crt --key kem.key http > $TMPDIR/server_kemtls_mut.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cafile kem-ca.crt --no-tickets --auth-certs client.crt --auth-key client.key --http servername > $TMPDIR/client_kemtls_mut.log
            echo "Done measuring mutual"
            measurementtype=kemtls-mut
        fi
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/kemtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/kemtls-dump.json
        popd > /dev/null

        echo "$dir KEM" >> $OUTFILE
        python3 count-hs-bytes.py $measurementtype $TMPDIR/kemtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/kemtls-dump.json /tmp
            mv $TMPDIR/kemtls-dump.pcap /tmp
            exit 1;
        fi
        # go back up in expected state
        pushd $dir > /dev/null
    fi
    if [ -f "kem.crt" ]; then
        echo "KEMTLS-PDK"
        if [[ "$dir" = *"mceliece"* ]]; then
            echo "Skipping McEliece"
            popd
            continue
        fi
        killall tlsserver tlsclient > /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/kemtls-dump.pcap &
        sharkpid=$!
        sleep 1
        if [[ "$dir" = *"-clauth-"* ]]; then
            ./tlsserver --port $PORT --certs kem.chain.crt --key kem.key --auth client-ca.crt --require-auth http > $TMPDIR/server_kemtlspdk_mut.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cached-certs kem.crt --auth-certs client.crt --auth-key client.key --cafile kem-ca.crt --no-tickets --http servername > $TMPDIR/client_kemtlspdk_mut.log
            echo "Done measuring mutual"
            measurementtype=kemtls-pdk-mut
        else
            ./tlsserver --port $PORT --certs kem.chain.crt --key kem.key http > $TMPDIR/server_kemtlspdk.log &
            SPID=$!
            sleep 0.5
            ./tlsclient --port $PORT --loops $loops --cached-certs kem.crt --cafile kem-ca.crt --no-tickets --http servername > $TMPDIR/client_kemtlspdk.log
            echo "Done measuring"
            measurementtype=kemtls-pdk
        fi
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/kemtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/kemtls-dump.json
        popd > /dev/null
        echo "$dir KEMPDK" >> $OUTFILE
        python3 count-hs-bytes.py $measurementtype $TMPDIR/kemtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/kemtls-dump.json /tmp
            mv $TMPDIR/kemtls-dump.pcap /tmp
            exit 1;
        fi
        # go back up in expected state
        pushd $dir > /dev/null
    fi
    popd
done

#rm -rf $TMPDIR
