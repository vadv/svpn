# Changelog

## v0.9.5

Geo exit and local-exit release.

- `multi` supports per-server `countries = ["NL", "DE"]`, Country Lite
  lookup and scoped sticky ASN ownership. Country constraints are applied
  before ASN selection; failover state is restored without snap-back.
- `local-exits = ["RU", "BY"]` sends matching IPv4 destinations through a
  local exit while other traffic uses the selected VPN server. TCP, UDP and
  ICMP use the existing SVPN packet path; no application TCP proxy is added.
- Local-exit has independent `server-up`/`server-down` hooks and SIGKILL
  recovery coverage: Linux sockets and TUN disappear, and new direct
  connections do not need a dead process.
- Added Country+ASN and local-exit Docker acceptance tests, including RU+BY,
  TCP/UDP/ICMP, restart and crash lifecycle. README documents the required
  Country DB and server hooks in Russian and English.

## v0.9.0

Sticky exit release.

- New `exit-policy = "sticky-asn"` for `multi` mode: every destination ASN
  group is pinned to one pool server via weighted rendezvous hashing, so a
  service sees the client from a single stable external IP while the owning
  server is alive. Failover moves a group to the next server in its
  rendezvous order; a rejoining ex-owner never snaps the group back.
- Geo data: DB-IP ASN Lite (CC BY 4.0), loaded once at startup from `geo-db`;
  a missing or corrupt file degrades to plain `balance` with a warning.
  `scripts/update-asn-db.sh` installs monthly updates atomically (staging +
  fsync + `.prev` rollback, systemd restart, cron-friendly exit codes).
- Failover transitions and first assignments that skip an unavailable
  primary are persisted to `exit-state` (default: `geo-db` with a
  `.state.json` suffix, batched writes); a 10-second startup grace lets a
  restored owner reconnect before its groups fail over.
- Addresses outside the database get a stable exit by address hash with no
  recorded state; node identity is `host:port`, so a stale state file after
  a config change is dropped with a warning.
- Metrics: `sticky_hit`, `sticky_miss`, `sticky_failover_moves` in the
  periodic stats report.
- e2e: sticky-asn suite (destination pinning, balance regression,
  failover + rejoin, restart restore). Docs: README (+en),
  THIRD-PARTY-NOTICES attribution for DB-IP.

## v0.8.0

Flow recovery release.

- Live flows survive transport loss: when a session's channel dies, the
  server keeps the session and its flow queues while the client rebinds
  to a replacement channel; TCP streams continue byte-exact over the new
  channel and UDP flows keep their flow id and sequence numbers.
- Recovery is proven by delivery, not intent: a flow counts as restored
  only after an observed peer packet (or a challenge round-trip for
  quiet flows); an abandoned recovery is logged with a reason.
- A failed fresh challenge channel no longer announces a lost data path
  while the verified incumbent keeps serving.
- Server-side TCP lifetime: half-closed and idle flows retire
  predictably; a dying session's flows get a best-effort RST toward the
  client TUN instead of hanging sockets.
- e2e: recovery suite (UDP continuation, byte-exact TCP continuation,
  silent retirement). Runbook: `recovery.md`.

## v0.7.1

Corrective release.

- A challenge attempt on an already-live channel reuses it instead of
  failing to bind its fixed port (`EADDRINUSE`). Reused channels are
  borrowed: attempt expiry or cancel no longer stops the shared channel,
  and a late reuse reply for a retired channel id is rejected instead of
  re-creating cipher state over its used key.

## v0.7.0

Continuous measurement release.

- Verdicts now read smoothed statistics instead of single bursts: every
  candidate keeps an EWMA of p90 with a deviation band (RFC 9002 alphas,
  window of 10 samples / 30 min). A challenger wins only when its band
  does not overlap the incumbent's and it is faster by 10% (floor 5 ms).
  One smoothed estimate replaces the two-burst confirmation; a 5 min
  cooldown after a switch stays.
- Background probing is continuous: in auto mode every candidate — the
  incumbent included — is probed once per `remeasure-interval` on average
  (default lowered 600 s → 60 s, jittered ±50%, `0` still disables).
  Healthy losers stay bound, so the next round reuses their channels
  instead of rebuilding them.
- Degradation reads the window: loss ≥ 3/10 in the latest burst, or the
  EWMA at ≥ 2× the window minimum. Slow drift raises both together and no
  longer triggers re-selection; a genuine spike still does.

## v0.6.1

Health-check visibility release.

- Periodic health bursts (every 30 s per server) now log their result:
  `ok` lines at `info` with p90 and echo count, degraded bursts and the
  re-selection trigger at `warn`.
- New `warn` log level between `error` and `info`: `--log-level warn` on
  the CLI, `log-level = "warn"` in TOML; the default stays `info`.

## v0.6.0

Adaptive transport re-selection release.

- `auto` no longer sticks to the first winner: it re-measures alternatives
  in the background every `remeasure-interval` (default 10 min, 0 disables,
  auto mode only) and whenever the live channel degrades (health burst
  loss ≥ 3/10 or p90 ≥ 2× the baseline taken at adoption).
- A challenger wins only with margin: its adjusted p90 must beat the
  incumbent's by at least 10% (floor 5 ms, TCP carries a 50 ms penalty),
  and the same candidate must win two rounds in a row before anything
  switches. One-off blips no longer flap the transport.
- Switching drains instead of killing: new flows open on the new channel,
  existing TCP flows keep flowing on the old one until they close.
- Fixed challenge probe flows never arming their bursts (the duplicate
  FlowOpen race), zombie health bursts blocking the slot forever, and
  challenge bursts queued behind an early server Committed never arming.

## v0.5.4

Transport health groundwork release.

- Server heartbeat stats now report why transports fail: per-transport
  counters for udp-refused, tcp-refused, no-server-answer, address-taken,
  and garbage — udp-garbage and tcp-garbage count datagrams that pass the
  outer protocol but fail the inner framing, the signature of a content
  filter mangling packets.
- New burst prober: a channel can carry a short ICMP echo series (10
  echoes, 100 ms apart) and report p90 RTT and loss. Groundwork for the
  upcoming background re-selection; no behavior change yet.

## v0.5.3

Hotfix release.

- Fixed the webrtc warmup panicking in the field: it ran in a bare
  `std::thread`, where `tokio::net::UdpSocket::from_std` has no reactor
  (`there is no reactor running` at `src/webrtc.rs`). The warmup now runs
  in `tokio::task::spawn_blocking`, which carries the runtime context.
  With the warmup dead, the first webrtc peer again paid the one-time
  crypto init inside the round and could miss the verdict window on
  higher-RTT links.
- Any panic in any thread now aborts the whole process. 0.5.2 showed the
  alternative: a fire-and-forget thread died silently and the VPN kept
  running degraded. Fail fast instead.

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

