# Build the GNU/Linux aarch64 binary with --platform linux/arm64.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
RUN test "$(uname -m)" = aarch64 || \
    { echo 'FATAL: use docker buildx build --platform linux/arm64' >&2; exit 1; }
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src
COPY scripts ./scripts
RUN --mount=type=cache,id=svpn-aarch64-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=svpn-aarch64-target,target=/src/target \
    cargo build --locked --release \
    && install -D target/release/svpn /out/svpn-aarch64-gnu \
    && readelf -h /out/svpn-aarch64-gnu | grep -q 'Machine:.*AArch64' \
    && readelf -l /out/svpn-aarch64-gnu | grep -q '/lib/ld-linux-aarch64.so.1' \
    && /out/svpn-aarch64-gnu --version \
    && cd /out && sha256sum svpn-aarch64-gnu
FROM scratch
COPY --from=build /out/ /
