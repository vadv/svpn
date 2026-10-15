FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
RUN test "$(uname -m)" = aarch64 || \
    { echo 'FATAL: use docker buildx build --platform linux/arm64' >&2; exit 1; }
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools perl make binutils \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add aarch64-unknown-linux-musl \
    && rustup component add clippy
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    CC_aarch64_unknown_linux_musl=musl-gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY README.md README.en.md ./
COPY .cargo ./.cargo
COPY src ./src
COPY tests/stderr.rs ./tests/stderr.rs
RUN --mount=type=cache,id=svpn-router-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=svpn-router-target,target=/src/target \
    cargo test --locked --target aarch64-unknown-linux-musl --all-targets \
    && cargo clippy --locked --target aarch64-unknown-linux-musl --all-targets -- -D warnings \
    && cargo build --locked --release --target aarch64-unknown-linux-musl \
    && install -D target/aarch64-unknown-linux-musl/release/svpn /out/svpn-openwrt-aarch64 \
    && readelf -h /out/svpn-openwrt-aarch64 | grep -q 'Machine:.*AArch64' \
    && /out/svpn-openwrt-aarch64 --version \
    && readelf -l /out/svpn-openwrt-aarch64 > /tmp/program-headers \
    && ! grep -q INTERP /tmp/program-headers \
    && readelf -d /out/svpn-openwrt-aarch64 > /tmp/dynamic-section \
    && ! grep -q NEEDED /tmp/dynamic-section \
    && cd /out && sha256sum svpn-openwrt-aarch64 > SHA256SUMS

FROM scratch
COPY --from=build /out/ /
