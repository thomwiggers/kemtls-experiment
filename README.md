# Post-Quantum TLS without handshake signatures

This repository accompanies

* Peter Schwabe, Douglas Stebila and Thom Wiggers. **More efficient KEMTLS with pre-distributed public keys.** ESORICS 2021.
* Peter Schwabe, Douglas Stebila and Thom Wiggers. **Post-quantum TLS without handshake signatures.** ACM CCS 2020.
* Peter Schwabe, Douglas Stebila and Thom Wiggers. **More efficient KEMTLS with pre-distributed public keys.** IACR Cryptology ePrint Archive, Report 2021/779. Updated online version. March 2022.
* Peter Schwabe, Douglas Stebila and Thom Wiggers. **Post-quantum TLS without handshake signatures.** IACR Cryptology ePrint Archive, Report 2020/534. Updated online version. March 2022.
* Fabio Campos, Jorge Chavez-Saab, Jesús-Javier Chi-Domínguez, Michael Meyer, Krijn Reijnders, Francisco Rodríguez-Henríquez, Peter Schwabe, Thom Wiggers. **Optimizations and Practicality of High-Security CSIDH.** IACR Cryptology ePrint Archive, Report 2023/793. October 2023.
* Thom Wiggers. **Post-Quantum TLS**. PhD thesis, January 2024.

```bibtex
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

@misc{EPRINT:SchSteWig20,
  author = {Peter Schwabe and Douglas Stebila and Thom Wiggers},
  title = {Post-quantum {TLS} without handshake signatures},
  year = 2022,
  month = mar,
  note = {full online version},
  url = {https://ia.cr/2020/534},
}

@inproceedings{ESORICS:SchSteWig21,
  title = {More efficient post-quantum {KEMTLS} with pre-distributed public keys},
  author = {Peter Schwabe and Douglas Stebila and Thom Wiggers},
  year = 2021,
  month = sep,
  url = {https://thomwiggers.nl/publication/kemtlspdk/},
  editor = {Bertino, Elisa and Shulman, Haya and Waidner, Michael},
  booktitle = {Computer Security -- ESORICS 2021},
  series = {Lecture Notes in Computer Science},
  publisher = {Springer International Publishing},
  address = {Cham},
  pages = {3--22},
  isbn = {978-3-030-88418-5},
  doi = {10.1007/978-3-030-88418-5_1},
}

@misc{EPRINT:SchSteWig21,
      author = {Peter Schwabe and Douglas Stebila and Thom Wiggers},
      title = {More efficient post-quantum {KEMTLS} with pre-distributed public keys},
      howpublished = {Cryptology ePrint Archive, Paper 2021/779},
      year = {2022},
      month = mar,
      note = {full online version},
      url = {https://eprint.iacr.org/2021/779}
}

@misc{EPRINT:CCCMRRSW23,
      author = {Fabio Campos and Jorge Chavez-Saab and Jesús-Javier Chi-Domínguez and Michael Meyer and Krijn Reijnders and Francisco Rodríguez-Henríquez and Peter Schwabe and Thom Wiggers},
      title = {Optimizations and Practicality of High-Security {CSIDH}},
      howpublished = {Cryptology ePrint Archive, Paper 2023/793},
      year = {2023},
      url = {https://eprint.iacr.org/2023/793}
}

@phdthesis{RU:Wiggers24,
    title = {Post-Quantum {TLS}},
    author = {Thom Wiggers},
    date = {2024-01-09},
    school = {Radboud University},
    address = {Nijmegen, The Netherlands},
    url = {https://thomwiggers.nl/publication/thesis/}
}

```

## Overview of this repository

The below are all [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules).
If you want to make a fork of this repository, you will need to also fork the relevant submodules and update your `.gitmodules`.
See also the notes below.

### Main folders

* ``rustls``: modified Rustls TLS stack to implement KEMTLS and post-quantum versions of "normal" TLS 1.3
* ``measuring``: The scripts to measure the above
* ``ring``: Modified version of Ring to allow for longer DER-encoded strings than typically expected from TLS instances.
* ``webpki``: Modified version of WebPKI to work with PQ and KEM public keys in certificates
* ``mk-cert``: Utility scripts to create post-quantum PKI for pqtls and KEMTLS.

### Supporting repositories

* [``oqs-rs``][]: Rust wrapper around ``liboqs``. Contains additional implementations of schemes (notably AVX2 implementations).
* ``mk-cert/xmss-rs``: Rust wrapper around the XMSS reference code, with our custom parameter set (``src/settings.rs``) and utilities for keygen and signing.

[``oqs-rs``]: https://github.com/open-quantum-safe/liboqs-rust

## Working with this repository

* **MAKE SURE TO CLONE WITH __ALL__ SUBMODULES**. There are submodules _within_ submodules, so clone with ``--recurse-submodules``.
* If you want to make a fork of this repository, you will need to also fork the relevant submodules and update your `.gitmodules`.
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
