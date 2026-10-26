# SVPN

SVPN is a client and server in one executable. It creates a secure IPv4
tunnel over SSH.

This guide starts with one complete setup that enables all three features:

- destinations in **Russia and Belarus** use `local-exit`;
- destinations in **the Netherlands and Germany** use two VPN exits;
- all other IPv4 destinations use both VPN exits with ASN affinity and weights.

Belarus uses the ISO code `BY`, Russia uses `RU`.

> **Platform: Linux.** This complete recipe uses a Linux client and two Linux
> servers. Do not copy its hooks to macOS. A macOS local-exit setup needs
> separate routing, forwarding and NAT commands.

## 1. Prepare the machines

| Machine | Requirements |
|---|---|
| Linux client | Root for this recipe, TUN, `iproute2`, `nftables`, `curl`, `gzip` and a normal default route through the physical interface |
| Each of the two VPSs | Linux, TUN, `iproute2`, `nftables`, root SSH and working Internet egress |
| Network | Permit SSH, TCP `41020` and UDP `60000–60009` to each VPS |

The VPS firewall must permit forwarding between TUN and the physical egress
interface. The NAT example does not change the existing firewall policy. Do
not disable the firewall.

Use the same SVPN version everywhere. Download the build for each machine's OS
and CPU architecture. Client and server are roles of one program, not a reason
to copy one platform-specific binary to every machine.

## 2. Install SVPN

Open [releases](https://github.com/vadv/svpn/releases) and download one
matching archive per machine:

- `svpn-<version>-linux-x86_64-gnu.tar.gz` for Linux x86_64;
- `svpn-<version>-macos-arm64.tar.gz` for macOS Apple Silicon;
- `svpn-<version>-openwrt-aarch64.tar.gz` for OpenWrt aarch64.

For Linux x86_64, run this on the client and each VPS. Replace the release
version first:

```bash
VERSION=0.9.6
curl -fLO "https://github.com/vadv/svpn/releases/download/v${VERSION}/svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
tar -xzf "svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

Extract one selected archive at a time. Install the `svpn` file from that
archive rather than mixing files from different builds.

## 3. Download country and ASN databases

Both databases belong on the **client**, not on the VPSs. The directory and
files are root-only:

```bash
sudo install -d -m 700 /etc/svpn
YEAR_MONTH=$(date +%Y-%m)

curl -fL "https://download.db-ip.com/free/dbip-country-lite-${YEAR_MONTH}.csv.gz" -o /tmp/country.csv.gz
gzip -dc /tmp/country.csv.gz | sudo tee /etc/svpn/country.csv >/dev/null

curl -fL "https://download.db-ip.com/free/dbip-asn-lite-${YEAR_MONTH}.csv.gz" -o /tmp/asn.csv.gz
gzip -dc /tmp/asn.csv.gz | sudo tee /etc/svpn/asn.csv >/dev/null
sudo chmod 600 /etc/svpn/country.csv /etc/svpn/asn.csv
```

Country Lite maps destination addresses to countries. ASN Lite enables
`sticky-asn`. You can use `scripts/update-asn-db.sh` from the source tree for
later ASN updates. A source checkout is not needed for the initial download.

## 4. Check SSH

Keep the private key on the client. Authorize its public key for `root` on
both VPSs. Test both logins before starting SVPN:

```bash
ssh -i /absolute/path/to/key root@nl.example.com
ssh -i /absolute/path/to/key root@de.example.com
```

Use an absolute key path. Load passphrase-protected keys into `ssh-agent`
before starting. When using `sudo -E`, agent preservation depends on the sudo
policy.

Without `hostkey`, SVPN uses TOFU and stores the fingerprint in its own
known-hosts file. For strict verification, obtain the fingerprint from your
provider and add `hostkey = "SHA256:..."` to each server. Do not add an empty
`hostkey` value.

## 5. Create one configuration

Run `sudoedit /etc/svpn/vpn.toml`. Replace `nl.example.com` and `de.example.com` with the
servers' IPv4 addresses in `servers` **and in the hooks**. Replace the key
path.

```toml
mode = "multi"
exit-policy = "sticky-asn"
country-db = "/etc/svpn/country.csv"
geo-db = "/etc/svpn/asn.csv"
exit-state = "/var/lib/svpn/exits.json"
local-exits = ["RU", "BY"]

ssh-user = "root"
ssh-identity = "/absolute/path/to/key"
ssh-port = 22
ssh-remote-bin = "/usr/local/bin/svpn"
mimic = ["ssh"]
tcp-port = 41020
udp-port-range = "60000-60009"

# Protect the VPS addresses before replacing the default route. This assumes
# no pre-existing host routes for these addresses.
up-command = "wan=$(ip route show default | awk 'NR==1{print $5}'); for ip in nl.example.com de.example.com; do ip route replace \"$ip/32\" dev \"$wan\"; done; ip route replace 0.0.0.0/1 dev \"$SVPN_TUN_NAME\"; ip route replace 128.0.0.0/1 dev \"$SVPN_TUN_NAME\""
down-command = "for ip in nl.example.com de.example.com; do ip route del \"$ip/32\" 2>/dev/null || true; done"

# These server hooks run on each VPS and at the local-exit on the client.
server-up = '''
sysctl -qw net.ipv4.ip_forward=1
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((100 + n))
table=svpn_egress_$n
wan=$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
ip rule add pref "$table_id" from "$SVPN_PEER_ADDR" table "$table_id" 2>/dev/null || true
ip route replace default dev "$wan" table "$table_id"
nft delete table inet "$table" 2>/dev/null || true
nft -f - <<EOF
add table inet $table
add chain inet $table postrouting { type nat hook postrouting priority srcnat; }
add rule inet $table postrouting ip saddr $SVPN_PEER_ADDR masquerade
EOF
'''
server-down = '''
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((100 + n))
ip rule del pref "$table_id" 2>/dev/null || true
ip route flush table "$table_id" 2>/dev/null || true
nft delete table inet "svpn_egress_$n" 2>/dev/null || true
'''

[[servers]]
address = "nl.example.com"
weight = 3
countries = ["NL", "DE"]

[[servers]]
address = "de.example.com"
weight = 1
countries = ["NL", "DE"]
```

Weights `3` and `1` mean an approximate 3:1 distribution. With `sticky-asn`,
addresses in one network keep their selected exit while it remains healthy.
Weights affect owner selection, not every individual packet.

### How the path is selected

| Destination | Path |
|---|---|
| `RU` or `BY` | `local-exit` through the local SVPN server and physical egress |
| `NL` or `DE` | Only servers listing that country in `countries` |
| Any other country or an address outside Country DB | Both example servers, using ASN affinity and weights |

One country can have several servers. `countries` restricts selection for that
country but does not remove the server from the general pool for other
countries. A server without `countries` also participates in ordinary
selection.

`local-exit` is not a TCP proxy. SVPN forwards IPv4 packets through its local
server. It needs `server-up` and `server-down`. Return routes are managed by
SVPN automatically. The hook sends packets sourced from `SVPN_PEER_ADDR`
through the physical uplink instead of back into the primary TUN.

The example `server-up` enables IPv4 forwarding and does not restore its
previous value on shutdown. It assumes no pre-existing host routes to
`nl.example.com` or `de.example.com`. If you already have such routes, save them and add
restoration to your own `down-command`.

## 6. Start and verify

Start in the foreground:

```bash
sudo -E svpn multi --config /etc/svpn/vpn.toml
```

Wait for both remote exits and `local-exit: ready`. Verify four things:

1. **Connectivity.** Check a responding IPv4 address with `ping` or `curl`.
2. **local-exit.** Choose a responding address from a `RU` or `BY` range in
   `/etc/svpn/country.csv`. The `local: opened` counter should increase.
3. **VPN.** An `NL` or `DE` address should open a flow on one VPS. An address
   in another country should also use one of the two VPSs.
4. **Stable ownership.** Repeated flows to addresses in one network should use
   the same server. When the owner fails, new flows move to a reserve server.
   Recovery of the old server does not cause snap-back.

A single `ping 1.1.1.1` does not verify Geo routing or sticky ASN. Use
addresses present in the installed Country DB and responding to the selected
protocol.

After verification, stop the foreground command with `Ctrl-C` and enable the
service:

```bash
sudo install -d -m 700 /etc/systemd/system
sudo tee /etc/systemd/system/svpn.service >/dev/null <<'EOF'
[Unit]
Description=SVPN
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/svpn multi --config /etc/svpn/vpn.toml
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now svpn
systemctl status svpn
journalctl -u svpn -f
```

## 7. Use only one feature

Only a single VPN between client and server:

```bash
sudo svpn root@nl.example.com
```

Sticky ASN without local-exit:

```toml
mode = "multi"
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
```

Country selection without local-exit:

```toml
mode = "multi"
country-db = "/etc/svpn/country.csv"

[[servers]]
address = "nl.example.com"
countries = ["NL"]

[[servers]]
address = "de.example.com"
countries = ["DE"]
```

`local-exits` and `countries` require `country-db`. `sticky-asn` requires
`multi` and `geo-db`. Do not add settings that your scenario does not use.

## 8. Update databases

SVPN loads CSV files at startup and does not reload them live. Replace the
files and restart the service:

```bash
sudo systemctl restart svpn
```

For ASN, `scripts/update-asn-db.sh` downloads and validates a new database and
keeps the previous file as `asn.csv.prev`. The script is in the source tree,
not in the binary archive.

## 9. Reference notes

### Transport

The default is SSH camouflage with UDP packet transport. SSH manages the
connection. If UDP is blocked, set `mimic = "ssh"` and `tcp-port`. UDP ports
are configured as a pair in `udp-ports = [60000, 60009]`.

| `mimic` | Use |
|---|---|
| `ssh` | SSH camouflage with UDP or TCP transport |
| `mosh` | Mosh camouflage over UDP |
| `webrtc` | WebRTC-like camouflage over UDP |
| `quic` | QUIC camouflage over UDP |

### Hooks

`up-command` and `down-command` run on the client. `server-up` and
`server-down` run on VPSs and at the local-exit. Hooks receive
`SVPN_TUN_NAME`, `SVPN_PEER_ADDR`, `SVPN_PEER_MTU`, `SVPN_REMOTE_BIN` and
`SVPN_EVENT`. The timeout is 10 seconds.

Use `up-script`, `down-script`, `server-up-script` and
`server-down-script` to move commands into files. Relative paths are based on
the configuration directory. Client scripts must invoke
`/usr/local/bin/svpn --tun-up` or `--tun-down`.

### Readiness

`svpn --probe` with `SVPN=1` returns 0 only when the channel is ready. Repeated
runs with the same configuration use address pairs from `10.77.0.0/16`. If a
pair conflicts, inspect addresses with `ip addr`.

### ASN owners

`exit-state` stores selected owners. By default, the state path is derived
from `geo-db` with a `.state.json` suffix. It survives restarts. Snap-back is
not performed.

### Limits

- Only IPv4 is tunnelled. This configuration does not protect IPv6.
- DNS is not changed automatically. Choose DNS separately.
- Country and ASN databases classify IP addresses, not domains. Selection
  happens after name resolution.
- The complete Linux recipe uses TUN, root, `iproute2` and `nftables`.
- Client hooks do not run after `SIGKILL`. The kernel closes TUN and sockets.
  The next start must restore its routes and rules. Do not use hooks for
  irreversible changes to resources you do not own.

## More information

- `svpn --help` — command reference.
- `svpn root@server --dry-run` — remote SSH commands without changes.
- [CHANGELOG](CHANGELOG.md) — version history.
- [Protocol](docs/PROTOCOL.md) — transport details.
- [Russian README](README.md).

## Build

```bash
cargo build --release --target x86_64-unknown-linux-gnu
cargo test --workspace
```

Before a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
uvx ruff@0.14.3 check
uvx ruff@0.14.3 format --check
python3 e2e/test_artifacts.py
python3 e2e/test_groups.py
python3 e2e/test_package.py
```
