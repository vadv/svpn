# SVPN

SVPN is a client and server in one executable. It creates a secure IPv4
tunnel over SSH.

This guide starts with one complete setup that enables all three features:

- destinations in `local-exits` use the local exit.
- destinations in selected countries use two VPN exits.
- all other IPv4 destinations use both VPN exits with ASN affinity and weights.

> **Platform: Linux.** This complete recipe uses a Linux client and two Linux
> servers. Do not copy its hooks to macOS. A macOS local-exit setup needs
> separate routing, forwarding and NAT commands.

## 1. Prepare the machines

| Machine | Requirements |
|---|---|
| Linux client | Root for this recipe, TUN, `iproute2`, `nftables`, `flock`, `curl`, `gzip` and a default route through the physical interface and gateway |
| Each of the two VPSs | Linux, TUN, `iproute2`, `nftables`, root SSH and working Internet egress |
| Network | Permit SSH, TCP `41020` and UDP `60000–60009` to each VPS |

Enable forwarding on the client and on every VPS. SVPN does not change this
shared setting or restore it on exit:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/90-svpn.conf
sudo sysctl --system
```

The VPS firewall must permit forwarding between TUN and the physical egress
interface. Configure NAT without disabling the firewall.

Use the same SVPN version everywhere. Download the build for each machine's OS
and CPU architecture. Client and server are roles of one program, not a reason
to copy one platform-specific binary to every machine.

## 2. Install SVPN

Open [releases](https://github.com/vadv/svpn/releases) and download one
matching archive per machine:

- `svpn-<version>-linux-x86_64-gnu.tar.gz` for Linux x86_64.
- `svpn-<version>-macos-arm64.tar.gz` for macOS Apple Silicon.
- `svpn-<version>-openwrt-aarch64.tar.gz` for OpenWrt aarch64.

For Linux x86_64, run this on the client and each VPS. Replace the release
version first:

```bash
VERSION=0.9.7
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
later ASN updates.

The hooks are already in the extracted archive for the same version. Run these
commands on the client:

```bash
sudo install -d -m 755 /usr/local/lib/svpn
sudo install -m 755 client-hooks/client-up /usr/local/lib/svpn/client-up
sudo install -m 755 client-hooks/client-down /usr/local/lib/svpn/client-down
```

Install the server hooks from the archive on each VPS:

```bash
sudo install -d -m 700 /etc/svpn
sudo install -m 755 scripts/server-up /etc/svpn/server-up
sudo install -m 755 scripts/server-down /etc/svpn/server-down
```

You do not need to start `svpn serve` manually on a VPS. The client starts it
over SSH. `server-up` and `server-down` belong only to those remote processes.

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

Without `ssh-host-key`, SVPN uses TOFU and stores the fingerprint in its own
known-hosts file. For strict verification, obtain the fingerprint from your
provider and add `ssh-host-key = "SHA256:..."` to each server. Do not add an
empty value.

## 5. Create one configuration

Run `sudoedit /etc/svpn/vpn.toml`. Replace `nl.example.com` and `de.example.com` with the
servers' IPv4 addresses in `servers` **and in the hooks**. Replace the key
path and replace `eth0` with the physical uplink name on each machine.

```toml
exit-policy = "sticky-asn"
country-db = "/etc/svpn/country.csv"
geo-db = "/etc/svpn/asn.csv"
exit-state = "/etc/svpn/exits.json"
local-exits = ["RU", "BY"]

ssh-user = "root"
ssh-identity = "/absolute/path/to/key"
ssh-port = 22
ssh-remote-bin = "/usr/local/bin/svpn"
mimic = ["ssh"]
tcp-port = 41020
udp-port-range = "60000-60009"

# Regular client hooks for the primary TUN and local-exit.
up-command = "/usr/local/lib/svpn/client-up eth0 nl.example.com de.example.com"
down-command = "/usr/local/lib/svpn/client-down eth0 nl.example.com de.example.com"

# Only for remote VPN servers. local-exit never receives them.
server-up = "/etc/svpn/server-up eth0"
server-down = "/etc/svpn/server-down"

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
| A country in `local-exits` | `local-exit` through the local SVPN server and physical egress |
| `NL` or `DE` | Only servers listing that country in `countries` |
| Any other country or an address outside Country DB | Both example servers, using ASN affinity and weights |

One country can have several servers. `countries` restricts selection for that
country but does not remove the server from the general pool for other
countries. A server without `countries` also participates in ordinary
selection.

`local-exit` is not a TCP proxy. SVPN forwards IPv4 packets through its local
server and uses the regular client `up-command` and `down-command`. For the
primary TUN, hooks protect the VPS routes and send other traffic through the
VPN. For local-exit, they enable forwarding and NAT on the physical interface.
Each TUN receives its own environment variables.
`server-up` and `server-down` belong only to VPS servers.

## 6. Start and verify

Start in the foreground:

```bash
sudo -E svpn multi --config /etc/svpn/vpn.toml
```

Wait for both remote exits and `local-exit: ready`. Verify four things:

1. **Connectivity.** Check a responding IPv4 address with `ping` or `curl`.
2. **local-exit.** Choose a responding address from a country in `local-exits`
   in `/etc/svpn/country.csv`. The `local: opened` counter should increase.
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
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
```

Country selection without local-exit:

```toml
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

The default is SSH camouflage with UDP. If UDP is blocked, set
`mimic = ["ssh"]` and `tcp-port = 41020`. Set the UDP range with
`udp-port-range = "60000-60009"`.

### Hooks

`up-command` and `down-command` run on the client for the primary TUN and
local-exit. `server-up` and `server-down` run only on VPSs. Client commands can use
`up-script` and `down-script`. Hooks receive `SVPN_EVENT`, `SVPN_TUN_NAME`,
`SVPN_TUN_ADDR`, `SVPN_PEER_ADDR` and `SVPN_SESSION_ID`. The timeout is 10
seconds.

### Readiness

In foreground, look for `serving` and `local-exit: ready`. With systemd, use
`journalctl -u svpn -f`. Repeated runs of the same configuration use address
pairs from `10.77.0.0/16`. If a pair conflicts, inspect addresses with
`ip addr`.

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
