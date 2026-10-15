# Build the GNU/Linux x86_64 binary with --platform linux/amd64.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
RUN test "$(uname -m)" = x86_64 || \
    { echo 'FATAL: use docker buildx build --platform linux/amd64' >&2; exit 1; }
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src
RUN --mount=type=cache,id=svpn-x86-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=svpn-x86-target,target=/src/target \
    cargo build --locked --release \
    && install -D target/release/svpn /out/svpn-x86_64-gnu \
    && readelf -h /out/svpn-x86_64-gnu | grep -q 'Machine:.*Advanced Micro Devices X86-64' \
    && readelf -l /out/svpn-x86_64-gnu | grep -q '/lib64/ld-linux-x86-64.so.2' \
    && /out/svpn-x86_64-gnu --version \
    && cd /out && sha256sum svpn-x86_64-gnu
FROM scratch
COPY --from=build /out/ /
