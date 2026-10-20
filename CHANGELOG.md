# Changelog

Append-only: new releases go on top, past entries never change.
Each section starts with `## vX.Y.Z` matching the git tag. The release
pipeline publishes exactly that section as the GitHub release notes, so a
release without a changelog section fails the pipeline.

## v0.4.0

Server hooks and robustness release.

- Server-side `up`/`down` hooks configured from the client TOML or CLI
  (`server-up`/`server-down`, per-server override): the server runs `up`
  after its TUN is ready, returns the captured result, and the client fails
  fast if it failed. `down` runs when the session ends. Nothing to install
  on the server.
- Hook output capture is bounded: 600 bytes per stream, sanitized so the
  worst-case JSON always fits the control channel line limit.
- Hook output draining survives detached grandchild processes holding the
  pipes (1s read grace instead of an indefinite hang).
- `ssh-identity` now accepts only an unencrypted private key file. Without
  the flag the keys come from the SSH agent. Passing a `.pub` file is a
  configuration error with a hint.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.
## v0.3.0

Field diagnostics and robustness release.

- Server now logs its active strategies and TCP fallback/camouflage on startup.
- Server `flow_open` log includes the transport (strategy) of each flow.
- Client logs selector backlog context when a pre-active packet is dropped,
  showing the preparing candidate, pre-active flow count, and queued bytes.
- Increased the selector pre-active queue limits (8 packets/flow, 2 MiB total)
  to absorb bursts while a UDP channel is being prepared.
- Pool retry log now includes the attempt number and the last failure reason.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

## v0.2.0

First binary release.

- IPv4 TUN VPN with SSH-key authentication and SSH control.
- UDP camouflage modes, a TCP fallback, single-server and server-pool modes.
- TOML configuration and client routing hooks.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

