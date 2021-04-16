# Post-Quantum TLS without handshake signatures

This repository accompanies

Peter Schwabe, Douglas Stebila and Thom Wiggers. **Post-quantum TLS without handshake signatures.** IACR Cryptology ePrint Archive, Report 2020/534. May 2020.

```
@unpublished{EPRINT:SchSteWig20,
  author = {Peter Schwabe and Douglas Stebila and Thom Wiggers},
  title = {Post-quantum {TLS} without handshake signatures},
  year = 2020,
  month = may,
  note = {preprint on {IACR} {ePrint} archive},
  url = {https://ia.cr/2020/534},
}
```

## Overview of this repository

### Main folders

* ``rustls-kemtls``: modified Rustls TLS stack to implement KEMTLS and post-quantum versions of "normal" TLS 1.3
* ``measuring``: The scripts to measure the above
* ``ring``: Modified version of Ring to allow for longer DER-encoded strings than typically expected from TLS instances.
* ``webpki``: Modified version of WebPKI to work with PQ and KEM public keys in certificates
* ``mk-cert``: Utility scripts to create post-quantum PKI for pqtls and KEMTLS.

### Supporting repositories

* [``oqs-rs``][]: Rust wrapper around ``liboqs``.
* ``mk-cert/xmss-rs``: Rust wrapper around the XMSS reference code, with our custom parameter set (``src/settings.rs``) and utilities for keygen and signing.
* ``csidh-rust``: Rust wrapper around the Meyer, Campos, Reith constant-time implementation of CSIDH.

[``oqs-rs``]: https://github.com/open-quantum-safe/liboqs-rust.git

## Working with this repository

* **MAKE SURE TO CLONE WITH __ALL__ SUBMODULES**. There are submodules _within_ submodules, so clone with ``--recurse-submodules``.
* The Dockerfile serves as an example of how everything can be compiled and how test setups can be created.
   It is used by the ``./measuring/script/create-experimental-setup.sh`` script, which serves as an example of its use.
* The `mk-certs` folder contains a python script, `encoder.py`, that can be used to create the required PKI.
   RSA certificates and X25519 certificates are available in subfolders.
   The certificates assume that the server hostname is ``servername``, so put this in your `/etc/hosts`.
   Alternatively, override it using the environment variables in the file (which is also how you set which algorithms are used).
* Experimenting with ``rustls`` can be done directly; use the ``rustls-mio`` subfolders
   and run ``cargo run --example tlsserver -- --help`` or ``cargo run --example tlsclient -- --help``.
* The measurement setup is handled in the `measuring/` folder. See the `./run_experiment.sh` script.
* Processing of results is done by the `./scripts/process.py` folder. It expects a `data` folder as produced by `./scripts/experiment.py`.
* Downloading archived results can be done through the scripts in ``measuring/archived-results/``
