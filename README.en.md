# SVPN

SVPN is a VPN client and VPN server in one executable. The client starts the
server on a VPS over SSH for the session: no daemon, systemd service or
separate configuration on the VPS.

## How it works

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 280}}}%%
flowchart TD
    app["🖥️ Application"] --> tun["Client TUN<br/>10.77.0.2"]
    tun --> brain("🧠 Path selection<br/>country · ASN<br/>local-exit")
    brain -->|"RU / BY"| local["🏠 Local exit<br/>NAT → WAN"]
    local --> home["🌍 home IP is visible"]
    brain -->|"rest of the world"| asn["🎯 sticky-ASN: each destination<br/>network (an ASN — Netflix,<br/>Google…) lives on one VPS"]
    asn --> mimic["🕵️ Camouflage — auto<br/>per channel: ssh · mosh · quic<br/>webrtc · obfs<br/>UDP 60000–60009<br/>or TCP 41020 if UDP blocked"]
    mimic -->|"Netflix traffic"| vps1["🖥️ VPS-1 · NL · weight 3<br/>decrypt → TUN → NAT"]
    mimic -->|"Google traffic"| vps2["🖥️ VPS-2 · DE · weight 1<br/>decrypt → TUN → NAT"]
    vps1 --> net1["🌍 VPS-1 IP is visible"]
    vps2 --> net2["🌍 VPS-2 IP is visible"]
    vps1 -.->|"if VPS-1 dies,<br/>networks move over"| vps2
    classDef brain fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px,color:#4a148c
    classDef local fill:#e8f5e9,stroke:#43a047,color:#1b5e20
    classDef asn fill:#fff8e1,stroke:#f9a825,color:#5d4037
    classDef vpn fill:#e3f2fd,stroke:#1e88e5,color:#0d47a1
    classDef edge fill:#eceff1,stroke:#546e7a,color:#263238
    class brain brain
    class local local
    class asn asn
    class mimic,vps1,vps2 vpn
    class home,net1,net2 edge
```

The client picks the path before encryption. Addresses in `local-exits` (for
example RU and BY) leave through the local exit — the site sees your home IP.
Everything else is encrypted and sent to a VPS — the site sees the server IP.
With several VPSs, `sticky-asn` pins every destination ASN to one server so a
service sees a stable external IP. Tunnel traffic is disguised as ordinary
protocols: the client probes them and keeps whichever works for the channel,
falling back to TCP when UDP is blocked.

## Quick start

You need a Linux client and one Linux VPS with root SSH. The client needs TUN,
`iproute2` and `nftables`. On the VPS allow SSH, TCP `41020` and UDP
`60000–60009`.

### 1. Install SVPN on the client

```bash
VERSION=0.9.6
curl -fLO "https://github.com/vadv/svpn/releases/download/v${VERSION}/svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
tar -xzf "svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

For aarch64 use the `linux-aarch64-gnu` archive. Besides the binary, the
archive carries `scripts/server-up` and `scripts/server-down` — the server
hooks.

### 2. Check SSH to the VPS

```bash
ssh -i /full/path/to/key root@203.0.113.10
```

If the key is passphrase-protected, load it into `ssh-agent` first. Instead of
root you can use a regular user with passwordless `sudo -n`.

### 3. Create the config

```bash
sudo install -d -m 700 /etc/svpn
sudoedit /etc/svpn/vpn.toml
```

```toml
# Your VPS address and SSH key.
server = "203.0.113.10"
ssh-user = "root"
ssh-identity = "/full/path/to/key"
tcp-port = 41020   # TCP fallback when UDP is blocked

# Hooks on the VPS: installed by svpn setup. They configure NAT and egress.
server-up = "/usr/local/lib/svpn/server-up"
server-down = "/usr/local/lib/svpn/server-down"

# Client routes: all IPv4 goes into the tunnel, the VPS stays reachable directly.
up-command = "wan=$(ip -4 route show default | awk 'NR==1{print $5}'); gw=$(ip -4 route show default | awk 'NR==1{print $3}'); ip route replace 203.0.113.10/32 via \"$gw\" dev \"$wan\"; ip route replace 0.0.0.0/1 dev \"$SVPN_TUN_NAME\"; ip route replace 128.0.0.0/1 dev \"$SVPN_TUN_NAME\""
down-command = "ip route del 203.0.113.10/32 2>/dev/null || true; ip route del 0.0.0.0/1 2>/dev/null || true; ip route del 128.0.0.0/1 2>/dev/null || true"
```

Replace the VPS address and the key path. The same address appears in
`up-command` and `down-command` — change it there too.

### 4. Prepare the VPS

```bash
sudo svpn setup --config /etc/svpn/vpn.toml
```

The command downloads the SVPN release on the VPS itself, installs the binary
and hooks and verifies the installation. It never modifies the config. Debian
12 and Rocky 10 on x86_64 and aarch64 are supported.

### 5. Start

```bash
sudo -E svpn --config /etc/svpn/vpn.toml
```

Stop with `Ctrl-C`. For systemd autostart see [ADVANCED.en.md](ADVANCED.en.md).

### 6. Verify

```bash
curl -4 https://ifconfig.me   # should print your VPS IP
ping -c1 1.1.1.1
```

If `ifconfig.me` shows the VPS IP, traffic goes through the tunnel.

## Next steps

Everything beyond a single server is covered in [ADVANCED.en.md](ADVANCED.en.md):

- several VPSs and weight-based distribution;
- country-based selection and `local-exit` for RU/BY;
- `sticky-asn` — a stable external IP per ASN;
- Country and ASN databases and their updates;
- hooks and environment variables;
- transport: mimic, TCP fallback, UDP port range;
- systemd and readiness checks;
- `svpn setup` details: environments, fallback, downgrade, statuses.

## Build

```bash
cargo build --release --target x86_64-unknown-linux-gnu
cargo test --workspace
```

Checks before a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
uvx ruff@0.14.3 check
uvx ruff@0.14.3 format --check
python3 e2e/test_artifacts.py
python3 e2e/test_groups.py
python3 e2e/test_package.py
```

## More information

- [ADVANCED.en.md](ADVANCED.en.md) — advanced configuration.
- [CHANGELOG](CHANGELOG.md) — version history.
- [Russian README](README.md).
- `svpn --help` — command reference.
