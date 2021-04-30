"""
This script counts the handshake bytes from a json-dumped tshark pcap

Measure handshakes using
```
tshark -i lo -w dump.pcap
```

Dump them to ``dump.json`` using
```
tshark -r dump.pcap -R tls -2 -Tjson --no-duplicate-keys > dump.json
```

(Requires a decently recent version of wireshark)

and then process the dump using this script.
"""


import itertools
import json
import os
import sys

import logging

if len(sys.argv) != 3 or sys.argv[1] not in ("pqtls", "pqtls-mut", "kemtls", "kemtls-mut", "kemtls-pdk", "kemtls-pdk-mut"):
    print(f"Usage: {sys.argv[0]} <TYPE> dump.json")
    sys.exit(1)

logging.basicConfig(level=getattr(logging, os.environ.get('LOGLEVEL', 'DEBUG').upper()))

with open(sys.argv[2]) as f:
    data = json.load(f)

client_port = None
server_port = None

class Packet:

    def __init__(self, packet):
        self._packet = packet
        self._tcp = packet["_source"]["layers"]["tcp"]
        self._tls = packet["_source"]["layers"].get("tls")

    @property
    def srcport(self):
        return self._tcp["tcp.srcport"]

    @property
    def dstport(self):
        return self._tcp["tcp.dstport"]

    @property
    def is_tls(self):
        return self._tls is not None

    @property
    def tls_records(self):
        if not self.is_tls:
            raise ValueError
        if isinstance(self._tls, list):
            all_records = []
            for tls_item in self._tls:
                records = tls_item['tls.record']
                if isinstance(records, list):
                    all_records.extend(records)
                else:
                    all_records.append(records)
            return all_records
        # just a singular tls record
        records = self._tls['tls.record']
        if isinstance(records, list):
            return records
        else:
            return [records]

    def is_css(self):
        return any(record.get('tls.change_cipher_spec', False) == "" for record in self.tls_records)

    @property
    def is_client_hello(self):
        hs = self.tls_records[0].get('tls.handshake')
        if not hs:
            return False
        return hs['tls.handshake.type'] == "1"

    @property
    def is_server_hello(self):
        hs = self.tls_records[0].get('tls.handshake')
        if not hs:
            return False
        return hs['tls.handshake.type'] == "2"

    @property
    def tcp_payload_size(self):
        return int(self._tcp['tcp.len'])

handshakes = []
for packet in [Packet(p) for p in data]:
    if not packet.is_tls:
        continue
    logging.debug(f"Packet: {packet.srcport} -> {packet.dstport}: {packet.tcp_payload_size} bytes")
    if packet.is_client_hello:
        client_port = packet.srcport
        server_port = packet.dstport
        handshakes.append([])
    handshakes[-1].append(packet)

# Now handshake contains a full TLS handshake

def length(record):
    return 5 + int(record['tls.record.length'])

# if PQTLS
TLS_TYPE = sys.argv[1]
if TLS_TYPE == "pqtls" or TLS_TYPE == "pqtls-mut":
    for handshake in handshakes:
        size = 0
        # Client Hello
        clmsgs = list(filter(lambda p: p.dstport == server_port, handshake))
        cmsgiter = itertools.chain.from_iterable(msg.tls_records for msg in clmsgs)

        assert clmsgs[0].is_client_hello
        size += (msgsize := length(next(cmsgiter)))
        logging.debug(f"Client hello size: {msgsize}")

        # Server Hello, CSS, EE, Cert, CertV, SFIN
        # chain all next server->client messages
        servmsgs = list(filter(lambda p: p.srcport == server_port, handshake))
        smsgiter = itertools.chain.from_iterable(msg.tls_records for msg in servmsgs)
        assert servmsgs[0].is_server_hello
        
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"Server hello size: {msgsize}")

        size += (msgsize := length(next(smsgiter)))
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        logging.debug(f"ChangeCipherSpec size: {msgsize}")
        
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"EncryptedExtensions size: {msgsize}")
        if TLS_TYPE == "pqtls-mut":
            size += (msgsize := length(next(smsgiter)))
            logging.debug(f"CertificateRequest size: {msgsize}")
        
        cert_size = (msgsize := length(next(smsgiter)))
        while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
            cert_size += (msgsize := length(next(smsgiter)))
        size += cert_size
        logging.debug(f"Certificate size: {cert_size}")
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"CertificateVerify size: {msgsize}")
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"ServerFinished size: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"

        # CSS, ClientFinished
        size += (msgsize := length(next(cmsgiter)))
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        logging.debug(f"ChangeCipherSpec size: {msgsize}")

        if TLS_TYPE == "pqtls-mut":
            cert_size += (msgsize := length(next(cmsgiter)))
            while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
                cert_size += (msgsize := length(next(cmsgiter)))
            size += cert_size
            logging.debug(f"Certificate size: {cert_size}")
            size += (msgsize := length(next(cmsgiter)))
            logging.debug(f"CertificateVerify size: {msgsize}")

        size += (msgsize := length(next(cmsgiter)))
        logging.debug(f"ClientFinished size: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"

        print(f"Total size: {size}")


if TLS_TYPE == "kemtls" or TLS_TYPE == "kemtls-mut":
    for handshake in handshakes:
        size = 0

        # Client msgs
        clmsgs = list(filter(lambda p: p.dstport == server_port, handshake))
        cmsgiter = itertools.chain.from_iterable(msg.tls_records for msg in clmsgs)
        # Server msgs
        servmsgs = list(filter(lambda p: p.srcport == server_port, handshake))
        smsgiter = itertools.chain.from_iterable(msg.tls_records for msg in servmsgs)

        # Client Hello
        ch = next(cmsgiter)
        assert clmsgs[0].is_client_hello
        size += (msgsize := length(ch))
        logging.debug(f"Client hello size: {msgsize}")

        # Server Hello, CSS, EE, Cert
        assert servmsgs[0].is_server_hello
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"Server hello size: {msgsize}")
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"ChangeCipherSpec size: {msgsize}")
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"EncryptedExtensions size: {msgsize}")

        if TLS_TYPE == "kemtls-mut":
            size += (msgsize := length(next(smsgiter)))
            logging.debug(f"CertificateRequest size: {msgsize}")

        cert_size = (msgsize := length(next(smsgiter)))
        while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
            cert_size += (msgsize := length(next(smsgiter)))
        size += cert_size
        logging.debug(f"Certificate size: {cert_size}")

        # CSS, CKEX
        size += (msgsize := length(next(cmsgiter)))
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        logging.debug(f"Client ChangeCipherSpec: {msgsize}")
        size += (msgsize := length(next(cmsgiter)))
        logging.debug(f"ClientCiphertext: {msgsize}")

        if TLS_TYPE == "kemtls-mut":
            # CCERT
            cert_size = (msgsize := length(next(cmsgiter)))
            while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
                cert_size += (msgsize := length(next(cmsgiter)))
            size += cert_size
            logging.debug("ClientCertificate size: %d", cert_size)
            
            # SKEX
            size += (msgsize := length(next(smsgiter)))
            logging.debug("ServerCiphertext size: %d", msgsize)

        # CFIN
        size += (msgsize := length(next(cmsgiter)))
        logging.debug(f"ClientFinished: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"

        # ServerFinished
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"ServerFinished size: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"


        print(f"Total size: {size}")

if TLS_TYPE == "kemtls-pdk" or TLS_TYPE == "kemtls-pdk-mut":
    for handshake in handshakes:
        size = 0
        # Client messages
        clmsgs = list(filter(lambda p: p.dstport == server_port, handshake))
        cmsgiter = itertools.chain.from_iterable(msg.tls_records for msg in clmsgs)
        # Server msgs
        servmsgs = list(filter(lambda p: p.srcport == server_port, handshake))
        smsgiter = itertools.chain.from_iterable(msg.tls_records for msg in servmsgs)

        # Client hello
        ch = next(cmsgiter)
        assert clmsgs[0].is_client_hello
        size += (msgsize := length(ch))
        logging.debug(f"ClientHello size (PDK): {msgsize}")

        if TLS_TYPE == "kemtls-pdk-mut":
            size += (msgsize := length(msg := next(cmsgiter)))
            logging.debug(f"ChangeCipherSpec: {msgsize}")
            
            cert_size = (msgsize := length(next(cmsgiter)))
            while msgsize == 16406:  # magic constant for large msgs that got fragmented by TLS
                cert_size += (msgsize := length(next(cmsgiter)))
            size += cert_size
            logging.debug("ClientCertificate size: %d", cert_size)

        # SH, CSS, EE, [SKEX], SFIN
        assert servmsgs[0].is_server_hello
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"Server hello size: {msgsize}")
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"ChangeCipherSpec size: {msgsize}")
        assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"EncryptedExtensions size: {msgsize}")

        if TLS_TYPE == "kemtls-pdk-mut":
            size += (msgsize := length(next(smsgiter)))
            logging.debug("ServerKemCiphertext size: %d", msgsize)
        
        size += (msgsize := length(next(smsgiter)))
        logging.debug(f"ServerFinished size: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"

        # [CSS], CFIN
        if not TLS_TYPE == "kemtls-pdk-mut":
            size += (msgsize := length(msg := next(cmsgiter)))
            assert msgsize == 6, f"expected ccs to be 6 bytes instead of {msgsize}"
            logging.debug(f"ChangeCipherSpec: {msgsize}")
        size += (msgsize := length(next(cmsgiter)))
        logging.debug(f"ClientFinished: {msgsize}")
        assert msgsize == 58, f"Expected finished size to be 58 bytes instead of {msgsize}"
       
        print(f"Total size: {size}")
