# SVPN v0.4.0

Server hooks and robustness release (pre-release).

- Server-side `up`/`down` hooks configured from the client TOML or CLI
  (`server-up`/`server-down`, per-server override): the server runs `up`
  after its TUN is ready, returns the captured result, and the client fails
  fast if it failed; `down` runs when the session ends. Nothing to install
  on the server.
- Hook output capture is bounded: 600 bytes per stream, sanitized so the
  worst-case JSON always fits the control channel line limit.
- Hook output draining survives detached grandchild processes holding the
  pipes (1s read grace instead of an indefinite hang).

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
