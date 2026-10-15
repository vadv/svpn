# SVPN v0.2.0

First binary release (pre-release).

- IPv4 TUN VPN with SSH-key authentication and SSH control.
- UDP camouflage modes and a TCP fallback; single-server and server-pool modes.
- TOML configuration and client routing hooks.

## Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

## Known issues

These fixes are deferred to later versions:

- A cancelled flow during a readiness check can leave state on its peer.
- TCP half-close tracking can close a connection too early or miss the FIN dwell timeout.
- A stalled TCP writer can retain a task and socket after its flow is removed.
- Conflicting fragments can consume the reassembly budget even after being discarded.

IPv6 is not carried or protected. SVPN does not configure DNS, routes, NAT, or
IP forwarding. Camouflage is not a guarantee of bypassing a particular filter.
