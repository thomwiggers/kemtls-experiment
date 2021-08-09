# Author: Thom Wiggers <thom@thomwiggers.nl>
# LICENSE: CC0
#
FROM rust:1.52-bullseye AS builder

SHELL ["/bin/bash", "-c"]

EXPOSE 8443 443/tcp

ADD https://apt.llvm.org/llvm-snapshot.gpg.key /llvm.key
RUN apt-key add /llvm.key

# Install requirements
RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-12 main" > /etc/apt/sources.list.d/llvm.list
RUN apt-get update  -qq
RUN apt-get install -qq -y pipenv libssl-dev cmake clang-12 llvm-12

# Default C compiler
# XXX: Somehow clang breaks.
ENV CC=gcc

# Rust options
ENV RUSTFLAGS "-C target-cpu=native -C link-arg=-s"
ENV RUST_MIN_STACK "20971520"

# Copy in the source
COPY mk-cert /usr/src/pqtls/mk-cert

# cleanup
WORKDIR /usr/src/pqtls/mk-cert
RUN ./clean.sh

# populate cargo build caches
WORKDIR /usr/src/pqtls/mk-cert/signutil
RUN echo "pub use oqs::sig::Algorithm::Dilithium2 as alg;" > src/lib.rs
RUN cargo update
RUN cargo build --release --examples

WORKDIR /usr/src/pqtls/mk-cert/kemutil
RUN echo "pub use oqs::kem::Algorithm::Kyber512 as thealgorithm;" > src/kem.rs
RUN cargo update
RUN cargo build --release

COPY secsidh-rs /usr/src/pqtls/secsidh-rs
WORKDIR /usr/src/pqtls/mk-cert/csidhutil
RUN echo "pub use secsidh::csidh2047d221 as csidh;" > src/instance.rs
RUN cargo update
RUN cargo build --release

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
# Precompile kemutil and signutil for build caches
WORKDIR /usr/src/pqtls/mk-cert/kemutil
RUN cargo build --release
WORKDIR /usr/src/pqtls/mk-cert/signutil
RUN cargo build --release --examples

# pre-Compile tlsserver and tlsclient examples
WORKDIR /usr/src/pqtls/rustls/rustls-mio/
RUN cargo build --release --example tlsserver && \
    cargo build --release --example tlsclient

# These must exactly match what is listed in the options of mk-cert/encoder.py
# (and those follow from liboqs)
ARG KEX_ALG="Kyber512"
# re-export build args as env vars
ENV KEX_ALG     $KEX_ALG

# Update the KEX alg
RUN sed -i 's@NamedGroup::[[:alnum:]]\+@NamedGroup::'${KEX_ALG}'@' /usr/src/pqtls/rustls/rustls/src/client/default_group.rs

# Compile tlsserver and tlsclient examples
RUN cargo build --release --example tlsserver && \
    cargo build --release --example tlsclient

# These must exactly match what is listed in the options of mk-cert/encoder.py
# (and those follow from liboqs)
ARG ROOT_SIGALG="Dilithium2"
ARG INT_SIGALG="Dilithium2"
ARG LEAF_ALG="Dilithium2"
ARG CLIENT_ALG="Kyber512"
ARG CLIENT_CA_ALG="Dilithium2"
ENV ROOT_SIGALG   $ROOT_SIGALG
ENV INT_SIGALG    $INT_SIGALG
ENV LEAF_ALG      $LEAF_ALG
ENV CLIENT_ALG   $CLIENT_ALG
ENV CLIENT_CA_ALG $CLIENT_CA_ALG

# actually generate the certificates
WORKDIR  /usr/src/pqtls/mk-cert
RUN      pipenv run python encoder.py

# Set up clean environment
FROM debian:bullseye

# Install libssl1.1
RUN apt-get update -qq \
 && apt-get install -qq -y libssl1.1 \
 && rm -rf /var/cache/apt

COPY --from=builder /usr/src/pqtls/rustls/target/release/examples/tlsserver /usr/local/bin/tlsserver
COPY --from=builder /usr/src/pqtls/rustls/target/release/examples/tlsclient /usr/local/bin/tlsclient
COPY --from=builder /usr/src/pqtls/mk-cert/*.crt /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.key /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.pub /certs/

WORKDIR /certs
CMD ["echo", "Run tls{server,client} for the rustls-mio server/client with KEX:", $KEX_ALG]
