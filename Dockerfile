FROM rust:latest AS builder

SHELL ["/bin/bash", "-c"]

EXPOSE 8443 443/tcp

ADD https://apt.llvm.org/llvm-snapshot.gpg.key /llvm.key

# Install requirements
RUN apt-key add /llvm.key \
 && echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster main" >> /etc/apt/sources.list.d/llvm.list \
 && apt-get update  -qq  \
 && apt-get install -qq -y \
        pipenv libssl-dev cmake clang llvm

# Default C compiler
# XXX: Somehow clang breaks.
ENV CC=gcc

# These must exactly match what is listed in the options of mk-cert/encoder.py
# (and those follow from pqclean / oqs
ENV ROOT_SIGALG "RainbowIaCyclic"
ENV INT_SIGALG  "Falcon512"
ENV KEX_ALG     "kyber512"

# Rust options
ENV RUSTFLAG "-C target-cpu=native"
ENV RUST_MIN_STACK "20971520"

# Copy in the source
COPY . /usr/src/pqtls

# Update the KEX alg
RUN sed -i 's@NamedGroup::[[:alnum:]]\+@NamedGroup::'${KEX_ALG^^}'@' /usr/src/pqtls/rustls/src/client/default_group.rs

# Compile tlsserver and tlsclient examples
WORKDIR /usr/src/pqtls/rustls/rustls-mio/
RUN cargo build --release --example tlsserver && \
    cargo build --release --example tlsclient

# Set up certificates (parameterised by the env vars)
WORKDIR  /usr/src/pqtls/mk-cert
RUN pipenv install

# actually generate the certificates
# FIXME support X25519/RSA
RUN pipenv run python encoder.py

FROM debian:buster

# Install libssl1.1
RUN apt-get update -qq \
 && apt-get install -qq -y libssl1.1 \
 && rm -rf /var/cache/apt

COPY --from=builder /usr/src/pqtls/rustls/rustls-mio/target/release/examples/tlsclient /usr/local/bin
COPY --from=builder /usr/src/pqtls/rustls/rustls-mio/target/release/examples/tlsserver /usr/local/bin
COPY --from=builder /usr/src/pqtls/mk-cert/*.crt /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.key /certs/
COPY --from=builder /usr/src/pqtls/mk-cert/*.pub /certs/

WORKDIR /certs
CMD ["tlsserver", "--help"]
