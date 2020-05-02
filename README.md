# Post-Quantum TLS without handshake signatures

This repository accompanies

TBD. _Post-Quantum TLS without handshake signatures_ TBD.

```
BIBTEX TO APPEAR HERE
```

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
