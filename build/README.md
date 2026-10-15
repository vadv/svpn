# Build and package SVPN

These commands build locally. They do not install, deploy, or publish anything.
Run them from the repository root. Keep `Cargo.lock`; use Rust 1.99.0, Python 3.9+
(with `file` and Git available), and Docker Buildx for the Linux builds.

| Package label | Binary | CPU / linking | Build environment |
| --- | --- | --- | --- |
| `linux-x86_64-gnu` | Linux client/server | x86_64 with AES; dynamic glibc | Pinned Debian Bookworm container |
| `openwrt-aarch64` | OpenWrt client | AArch64 with AES; static musl | Pinned ARM64 Linux container |
| `macos-arm64` | macOS client | Apple Silicon; libSystem | Native macOS |

The OpenWrt label is not a promise of support for arbitrary ARM64 Linux devices.
The GNU binary is **not static**; it needs the GNU loader and compatible glibc.
Container tests and `--version` smoke tests do not prove networking on an OpenWrt
device or an older macOS installation.

## Build GNU/Linux x86_64

```sh
docker buildx build --platform linux/amd64 -f build/x86_64.Dockerfile \
  --output type=local,dest=dist/raw-x86 .
python3 build/package.py linux-x86_64-gnu dist/raw-x86/svpn-x86_64-gnu
```

The recipe checks the ELF architecture, GNU loader, and executable startup.
It does not repeat the separate native Rust test job.

## Build OpenWrt AArch64

```sh
docker buildx build --platform linux/arm64 -f build/openwrt.Dockerfile \
  --output type=local,dest=dist/raw-openwrt .
python3 build/package.py openwrt-aarch64 dist/raw-openwrt/svpn-openwrt-aarch64
```

The recipe runs musl-target unit tests and Clippy, checks AArch64 startup,
and rejects an interpreter or dynamic-library dependency. Use an ARM64 host
for native tests; emulation on another architecture is not native verification.

## Build macOS arm64

```sh
test "$(uname -m)" = arm64
cargo +1.99.0 build --locked --release
./target/release/svpn --version
./target/release/svpn --help
python3 build/package.py macos-arm64 target/release/svpn
```

Do not change the label to Intel macOS without building and testing that target.

## Inspect the archive

`build/package.py` produces a `.tar.gz` and matching `.tar.gz.sha256` in
`dist/archives/`. Use `--output PATH` for a different directory; existing files
are never overwritten. The archive contains `svpn`, `build-info.json`, `LICENSE`, and
`THIRD-PARTY-NOTICES`.
The metadata records version, full commit, target, CPU/libc requirements, binary
SHA256, and the CI run ID when present. Version and commit describe the packager's
checkout, not proven build provenance. CPU/libc labels describe the selected
recipe's requirements; the file-format check does not establish those properties.
SHA256 identifies the binary bytes, not the source used to build them. A dirty
checkout is explicitly marked in both filename and metadata: its commit is a
**base commit**, not a claim that the binary came from that clean revision.

`THIRD-PARTY-NOTICES` is checked in with the lockfile digest. When dependencies
change, refresh it from their license files, including vendored C, upstream
workspace notices omitted from crates, and the compiler/runtime notices. Keep
the original copyright lines; an SPDX name alone is not a replacement. Update
runtime notices when changing the pinned toolchain or Linux build image.

The packager checks file format and labels, not runtime behavior. Identical
binary bytes and metadata produce identical archives; this does not claim
bit-for-bit reproducible compilation across different SDKs or environments.
The release job requires fresh builds from the tagged commit and all CI checks
to pass. It validates the complete artifact set, archive and binary checksums,
clean source metadata, version, commit, CI run ID, and included license notices.

Run the archive self-check without Docker or network access:

```sh
python3 tests/test_package.py
```

CI defines independent native build jobs using fresh hosted runners and no
shared project cache. The Linux images are pinned by digest. The native runner
labels follow [GitHub's runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Build jobs retain archives and checksums as workflow artifacts. A `v<version>`
tag matching Cargo's version triggers publication only after every check passes.
The publisher downloads artifacts from that same run, creates a draft release,
re-downloads and verifies its assets, then publishes it as a pre-release. Only
the publisher job has `contents: write`. Known issues are listed in
[RELEASE_NOTES.md](../RELEASE_NOTES.md).

Release files use stable names such as `svpn-0.2.0-linux-x86_64-gnu.tar.gz`.
The exact source commit remains in `build-info.json`. SVPN is MIT-licensed;
dependency notices travel inside each archive.
