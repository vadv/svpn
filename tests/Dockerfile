FROM rust:1.99.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY README.md README.en.md ./
COPY .cargo ./.cargo
COPY src ./src
COPY tests/stderr.rs ./tests/stderr.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release \
    && cp target/release/svpn /svpn

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server openssh-client iproute2 iputils-ping python3 libssl3 procps iptables nftables tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd
COPY --from=build /svpn /usr/local/bin/svpn
COPY tests /tests
