# SVPN v0.3.0

Field diagnostics and robustness release (pre-release).

- Server now logs its active strategies and TCP fallback/camouflage on startup.
- Server `flow_open` log includes the transport (strategy) of each flow.
- Client logs selector backlog context when a pre-active packet is dropped,
  showing the preparing candidate, pre-active flow count, and queued bytes.
- Increased the selector pre-active queue limits (8 packets/flow, 2 MiB total)
  to absorb bursts while a UDP channel is being prepared.
- Pool retry log now includes the attempt number and the last failure reason.

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
