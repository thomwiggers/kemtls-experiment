# Post-Quantum TLS without handshake signatures

This repository accompanies

Peter Schwabe, Douglas Stebila and Thom Wiggers. **Post-quantum TLS without handshake signatures.** IACR Cryptology ePrint Archive, Report 2020/534. May 2020.

```
@inproceedings{CCS:SchSteWig20,
  author = {Schwabe, Peter and Stebila, Douglas and Wiggers, Thom},
  title = {Post-Quantum {TLS} Without Handshake Signatures},
  year = {2020},
  isbn = {9781450370899},
  publisher = {Association for Computing Machinery},
  address = {New York, {NY}, {USA}},
  url = {https://thomwiggers.nl/publication/kemtls/},
  doi = {10.1145/3372297.3423350},
  booktitle = {Proceedings of the 2020 {ACM} {SIGSAC} Conference on Computer and Communications Security},
  pages = {1461–1480},
  numpages = {20},
  keywords = {transport layer security, key-encapsulation mechanism, {NIST PQC}, post-quantum cryptography},
  location = {Virtual Event, {USA}},
  series = {{CCS '20}}
}

@online{EPRINT:SchSteWig20,
  author = {Peter Schwabe and Douglas Stebila and Thom Wiggers},
  title = {Post-quantum {TLS} without handshake signatures},
  year = 2021,
  month = apr,
  note = {full online version},
  url = {https://ia.cr/2020/534},
}
```

## Overview of this repository

### Main folders

* ``rustls-kemtls``: modified Rustls TLS stack to implement KEMTLS
* ``rustls-pqtls``: Rustls with support for KEM kex and PQ signature schemes
* ``measuring``: The scripts to measure the above
* ``ring``: Modified version of Ring to work with KEMs and PQ signatures
* ``webpki``: Modified version of WebPKI to work with PQ and KEM public keys in certificates
* ``mk-cert``: Utility scripts to create post-quantum PKI for pqtls and KEMTLS

### Supporting repositories

* ``oqs-rs``: Rust wrapper around ``liboqs``.
    * ``oqs-rs/oqs-sys/liboqs`` is a version of ``liboqs`` with additional (AVX2) implementations
* ``pqcrypto``: Rust wrappers around ``PQClean``
    * ``pqcrypto/pqclean``: Modified version of PQClean with additional (AVX2) implementations
* ``mk-cert/xmss-rs``: Rust wrapper around the XMSS reference code, with our custom parameter set (``src/settings.rs``) and utilities for keygen and signing.
* ``csidh-rust``: Rust wrapper around the Meyer, Campos, Reith constant-time implementation of CSIDH.

### Miscelaneous dependencies

* ``tls-hacking``: Contains a generator for the ``src/msgs/enums.rs`` file in ``rustls``.
    Updating `enums.rs` is needed to add cryptographic primitives. The generator helps keeping enums in sync.

## Working with this repository

* **MAKE SURE TO CLONE WITH __ALL__ SUBMODULES**. There are submodules _within_ submodules, so clone with ``--recurse-submodules``.
* The Dockerfile serves as an example of how everything can be compiled and how test setups can be created.
   It is used by the ``./measuring/script/create-experimental-setup.sh`` script, which serves as an example of its use.
* The `mk-certs` folder contains a python script, `encoder.py`, that can be used to create the required PKI.
   RSA certificates and X25519 certificates are available in subfolders.
   The certificates assume that the server hostname is ``servername``.
* Experimenting with ``rustls-pqtls`` or ``rustls-kemtls`` can be done directly; use the ``rustls-mio`` subfolders
   and run ``cargo run --example tlsserver -- --help`` or ``cargo run --example tlsclient -- --help``.
* The measurement setup is handled in the `measuring/` folder. See the `./run_experiment.sh` script.
* Processing of results is done by the `./scripts/process.py` folder. It expects a `data` folder as produced by `./scripts/experiment.py`.
* Downloading archived results can be done through the scripts in ``measuring/archived-results/``
