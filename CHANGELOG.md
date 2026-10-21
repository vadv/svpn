# Changelog

## v0.5.2

Honest transport selection and quiet logs release.

- The verdict window now scales with the measured probe RTT: after the
  first verified echo the remaining candidates get `max(400 ms, 8 RTT)`,
  and every candidate that finishes its handshake inside the window
  extends it by another 6 RTT. webrtc and quic finally reach the verdict
  on links with RTT above ~40 ms instead of losing by construction.
- The round log names each silent candidate's stage (`handshake` or
  `probe`) and shows probe RTTs separately, so a blocked transport is
  distinguishable from a slow one.
- webrtc crypto is prewarmed in a background thread at startup: the
  first peer no longer pays ~340 ms of lazy initialization inside the
  session loop (measured on an OpenWrt router).
- Drop logs are classified: expected noise (IPv6 router chatter, IGMP,
  fragments, protocol races after `FlowClose`) is counted in stats but
  logged at debug. ERROR stays for bugs and real data loss. Hub drops
  before link selection no longer blame the first server's IP.
- The selector pre-active queue holds 64 packets per flow instead of 8,
  so a UDP burst in a flow's first RTT no longer triggers `selector
  queue full`; the 2 MiB byte budget still caps memory.

## v0.5.1

Transport selection release.

- All allowed candidates now arm in the same round: the CPU-heavy WebRTC
  peer builds in the background and can no longer delay the other
  candidates' start by ~300 ms.
- After the first verified ICMP echo the remaining candidates get a 400 ms
  grace window, driven by a dedicated timer; the verdict picks the lowest
  measured probe RTT (counted from the first send of the probe, not the
  attempt start), with TCP carrying a 50 ms penalty. UDP transports no
  longer lose photo-finishes to TCP or get punished for handshakes they had
  already finished.
- One completion rule for rounds: a round where every candidate answered
  or died decides immediately instead of waiting out the grace window.
- Fixed the fixed-TCP plane failing its round with `TCP attempt without
  start time`.

## v0.5.0

Automatic tunnel names and address assignment release.

- **Breaking: control protocol v2.** Client and server negotiate tunnel
  addresses during the handshake (`assigned`/`accept_addr`/`decline_addr`)
  and both sides must run 0.5.0. Upgrade the server together with the
  clients; mixing with 0.4.x fails fast at the greeting.
- `tun-name`, `peer-tun-name`, `tun-addr`, and `peer-addr` are optional now.
  Both sides pick free TUN names themselves and take an address pair from a
  built-in pool (255 pairs, `10.77.n.0/30`). Zero-addressing quick start:
  one flag-less `svpn single` is enough.
- Address pairs are claimed with loopback UDP port tokens: the kernel hands
  a pair to exactly one svpn process per host and releases it the moment the
  process dies, so parallel sessions never share addresses and nothing is
  left behind on disk.
- Server-pool members share one address pair, so every link of the pool
  keeps the same tunnel addresses and reconnects resume on the same pair.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

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

