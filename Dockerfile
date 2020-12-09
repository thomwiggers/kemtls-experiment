# Author: Thom Wiggers <thom@thomwiggers.nl>
# LICENSE: CC0
#
FROM rust:latest AS builder

SHELL ["/bin/bash", "-c"]

EXPOSE 8443 443/tcp

ADD https://apt.llvm.org/llvm-snapshot.gpg.key /llvm.key
RUN apt-key add /llvm.key

# Install requirements
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main" > /etc/apt/sources.list.d/llvm.list
RUN apt-get update  -qq
RUN apt-get install -qq -y pipenv libssl-dev cmake clang-10 llvm-10

# Default C compiler
# XXX: Somehow clang breaks.
ENV CC=gcc

# Rust options
ENV RUSTFLAGS "-C target-cpu=native -C link-arg=-s"
ENV RUST_MIN_STACK "20971520"

# Copy in the source
COPY mk-cert /usr/src/pqtls/mk-cert

# populate cargo build caches
WORKDIR /usr/src/pqtls/mk-cert/signutil
RUN echo "pub use oqs::sig::Algorithm::Dilithium2 as alg;" > src/lib.rs
RUN cargo build --release --examples

WORKDIR /usr/src/pqtls/mk-cert/kemutil
RUN echo "pub use pqcrypto::kem::kyber512::*;" > src/kem.rs
RUN cargo build --release --features pqclean

WORKDIR /usr/src/pqtls/mk-cert/xmss-rs
RUN cargo build --release

# Copy remaining sources
COPY webpki  /usr/src/pqtls/webpki
COPY ring    /usr/src/pqtls/ring
COPY rustls  /usr/src/pqtls/rustls

# Generate rustls build cache
WORKDIR /usr/src/pqtls/rustls/rustls-mio
RUN cargo build --release --examples

# Set up certificates (will be parameterised by the env vars)
WORKDIR  /usr/src/pqtls/mk-cert
RUN pipenv install

# These must exactly match what is listed in the options of mk-cert/encoder.py
# (and those follow from pqclean / oqs)
ARG KEX_ALG="kyber512"
# re-export build args as env vars
ENV KEX_ALG     $KEX_ALG

# Update the KEX alg
RUN sed -i 's@NamedGroup::[[:alnum:]]\+@NamedGroup::'${KEX_ALG^^}'@' /usr/src/pqtls/rustls/src/client/default_group.rs

# Compile tlsserver and tlsclient examples
WORKDIR /usr/src/pqtls/rustls/rustls-mio/
RUN cargo build --release --example tlsserver && \
    cargo build --release --example tlsclient

# These must exactly match what is listed in the options of mk-cert/encoder.py
# (and those follow from pqclean / oqs)
ARG ROOT_SIGALG="dilithium2"
ARG INT_SIGALG="dilithium2"
ARG LEAF_SIGALG="dilithium2"
ENV ROOT_SIGALG $ROOT_SIGALG
ENV INT_SIGALG  $INT_SIGALG
ENV LEAF_SIGALG $LEAF_SIGALG

# actually generate the certificates
# FIXME support X25519/RSA
WORKDIR  /usr/src/pqtls/mk-cert
RUN pipenv run python encoder.py

# Set up clean environment
FROM debian:buster

# Install libssl1.1
RUN apt-get update -qq \
 && apt-get install -qq -y libssl1.1 \
 && rm -rf /var/cache/apt

COPY --from=builder /usr/src/pqtls/rustls/rustls-mio/target/release/examples/tlsserver /usr/local/bin/tlsserver
COPY --from=builder /usr/src/pqtls/rustls/rustls-mio/target/release/examples/tlsclient /usr/local/bin/tlsclient
COPY --from=builder /usr/src/pqtls/mk-cert/*.crt /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.key /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.pub /certs/

WORKDIR /certs
CMD ["echo", "Run tls{server,client} for the rustls-mio server/client with KEX:", $KEX_ALG]
