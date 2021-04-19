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

export LOGLEVEL=INFO

rm -rf $OUTFILE

for dir in ../bin/*; do
    pushd $dir;
    if [ -f "signing.crt" ]; then
        echo "PQTLS"
        killall tlsserver tlsclient > /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/pqtls-dump.pcap &
        sharkpid=$!
        sleep 1
        ./tlsserver --port $PORT --certs signing.chain.crt --key signing.key http > /dev/null&
        SPID=$!
        sleep 0.5
        ./tlsclient --port $PORT --loops 10 --cafile signing-ca.crt --no-tickets --http servername > /dev/null
        echo "Done measuring"
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/pqtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/pqtls-dump.json
        popd
        echo "$dir PQTLS" >> $OUTFILE
        python3 count-hs-bytes.py pqtls $TMPDIR/pqtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/pqtls-dump.json /tmp
            mv $TMPDIR/pqtls-dump.pcap /tmp
            exit 1;
        fi
        # go back up into expected dir
        pushd $dir 
    fi
    if [ -f "kem.crt" ]; then
        echo "KEMTLS"
        killall tlsserver tlsclient > /dev/null
        echo Starting TSHARK
        tshark -i lo -w $TMPDIR/kemtls-dump.pcap &
        sharkpid=$!
        sleep 1
        ./tlsserver --port $PORT --certs kem.chain.crt --key kem.key http > /dev/null&
        SPID=$!
        sleep 0.5
        ./tlsclient --port $PORT --loops 10 --cafile kem-ca.crt --no-tickets --http servername > /dev/null
        echo "Done measuring"
        sleep 5
        kill -TERM $sharkpid $SPID
        tshark -r $TMPDIR/kemtls-dump.pcap -R tls -2 -Tjson --no-duplicate-keys > $TMPDIR/kemtls-dump.json
        popd
        echo "$dir KEM" >> $OUTFILE
        python3 count-hs-bytes.py kemtls $TMPDIR/kemtls-dump.json >> $OUTFILE
        ret=$?
        if [ $ret != 0 ]; then
            echo "Error occurred when processing"
            mv $TMPDIR/kemtls-dump.json /tmp
            mv $TMPDIR/kemtls-dump.pcap /tmp
            exit 1;
        fi
        # go back up in expected state
        pushd $dir
    fi
    popd
done

rm -rf $TMPDIR
