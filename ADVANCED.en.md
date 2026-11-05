# SVPN: advanced configuration

The basic single-server setup is described in [README.en.md](README.en.md).
This file covers several VPSs, the sticky policy, GeoIP databases, hooks,
transport, systemd and `svpn setup` details. The configuration file is HCL.

## Several VPSs and sticky

A complete example: two VPSs, `sticky` blocks by names, countries and ASN,
a local egress for RU/BY and weight-based distribution. Replace the server
addresses and the key path.

```hcl
# vpn.hcl
ssh {
  user       = "root"
  identity   = "/full/path/to/key"
  port       = 22
  remote_bin = "/usr/local/bin/svpn"
}

transport {
  mimic      = ["ssh"]
  tcp_port   = 41020  # fixed TCP fallback; required with mimic = ["ssh"] and no UDP
  udp_ports  = "60000-60009"
}

geo {
  db = "/etc/svpn/asn.csv"         # for asn selectors and strategy = "sticky-asn"
}

country {
  db = "/etc/svpn/country.csv"     # for countries selectors
}

fallback_sticky {
  strategy = "sticky-asn"          # how the pool serves traffic outside sticky blocks
  state    = "/etc/svpn/exits.json"
}

server "nl" {
  address = "203.0.113.10"
  weight  = 3
}

server "de" {
  address = "198.51.100.20"
  weight  = 1
}

# Block order = priority: first match wins.
sticky "claude" {
  names = ["claude.ai", "anthropic.com"]
  via   = ["nl"]                   # one element = a hard pin
  every = "5m"                     # name re-resolve (min 5s, default 300s)
}

sticky "eu" {
  countries = ["NL", "DE"]
  via       = ["de", "nl"]         # rendezvous: stable + failover
}

sticky "home" {
  countries = ["RU", "BY"]
  via       = local                # local egress, outside the VPN
}
```

## How the path is selected

Routing is exactly two mechanisms:

1. **sticky blocks** — ordered first-match: the destination address is checked
   against the blocks top to bottom; the first match wins. On a match:
   - `via = ["…"]` — the whole group is pinned to one server from the list
     (rendezvous by weights; a server failure moves the group to the next one,
     and recovery does not move it back — no snap-back);
   - `via = local` — packets leave through the local SVPN server and the
     physical uplink (the site sees your home IP). No databases are needed
     when the selector is `names` or `ips`.
2. **fallback_sticky** — traffic matched by no block: `balance` (weighted per
   flow) or `sticky-asn` (ASN groups with a stable owner; requires `geo.db`).

| Destination from the example | Path |
|---|---|
| IPs that claude.ai / anthropic.com resolve to | Always via `nl` |
| NL and DE addresses | One owner from `de`+`nl`, failover between them |
| RU and BY addresses | Local egress, outside the VPN |
| Everything else | `sticky-asn`: an ASN group → one owner from the whole pool |

`weight` is the share of groups a server owns: weights 3 and 1 give a rough
3:1 distribution. Weights affect owner selection, not individual packets.

### Selectors and the resolver

- Exactly one selector per block: `names`, `countries`, `ips` or `asn` — all
  lists; the group is the union of the elements.
- `names`: SVPN itself resolves the names with the system resolver
  episodically — the first resolve happens at startup, then every `every`.
  Until the first resolve the addresses follow the fallback. An IP missing
  from two consecutive resolves leaves the group (protection against CDN
  re-leasing). A resolve error keeps the previous IP set.
- `ips`: exact addresses and CIDRs; CIDR host bits must be zero.
- `countries` requires `country.db`; `asn` and `strategy = "sticky-asn"`
  require `geo.db`.
- The same selector in two blocks is an error: the second would be dead
  config.

Owners of sticky groups and ASN groups persist in one `state` file and
survive restarts: a restart during an outage does not snap groups back.

## Country and ASN databases

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

Country Lite determines the destination country (needed by `countries`
selectors); ASN Lite determines the network (needed by `asn` selectors and
`sticky-asn`). SVPN loads the CSV files at startup and does not re-read them
live. Update the files and restart the service:

```bash
sudo systemctl restart svpn
```

For ASN there is `scripts/update-asn-db.sh` in the source tree. It downloads
a new database, validates it and keeps the previous one as `asn.csv.prev`.

## Server hooks

`server_up` and `server_down` run on the VPSs and at the local egress on the
client. When these fields are absent, `serve` runs the embedded
`scripts/server-up` and `scripts/server-down` from the current binary.

Global defaults live in the `hooks` block; per-server overrides live inside
the server block (heredocs keep multiline commands readable):

```hcl
hooks {
  server_up = <<EOF
sysctl -w net.ipv4.ip_forward=1
EOF
}

server "de" {
  address    = "198.51.100.20"
  server_up = "echo custom variant for this server only"
}
```

To customize the embedded script, inspect it, save it, edit it and point the
config at it:

```bash
svpn example server-up > server-up
svpn example server-down > server-down
$EDITOR server-up server-down
```

Hooks receive these environment variables:

- `SVPN_EVENT` — `up` or `down`;
- `SVPN_TUN_NAME` — the TUN name;
- `SVPN_TUN_ADDR` — this side's tunnel address;
- `SVPN_PEER_ADDR` — the other side's tunnel address;
- `SVPN_SESSION_ID` — the process PID.

The timeout is 10 seconds. A failing `up` prevents the session from starting;
a failing `down` is only logged.

## Client hooks

In auto mode the embedded `scripts/client-up` and `scripts/client-down` from
the current binary run. The exact text can be inspected before starting:

```bash
svpn example client-up
svpn example client-down
```

The script receives `SVPN_SERVER_ADDRS` and `SVPN_OS`, then:

1. adds a `/32` host route to every VPS through the original path;
2. adds `0.0.0.0/1` and `128.0.0.0/1` through the TUN;
3. removes only this session's routes on shutdown.

Manual overrides live in the `hooks` block: `up_command`/`down_command` (a
string for `/bin/sh -c`) or `up_script`/`down_script` (a path to an executable
file). Directions are independent: you can keep the automatic up and provide a
custom down. An explicit command disables the embedded script only for its
own direction. Commands receive the same variables as server hooks and share
the same 10-second timeout.

## SSH checks and host keys

The client needs a private key, and its public part must be authorized on the
VPS. Use an absolute key path (relative paths in the config are resolved
against the config file's directory). If the key is passphrase-protected,
load it into `ssh-agent` first.

Without `host_key` SVPN uses TOFU and stores the fingerprint in its
known-hosts file. For strict checking obtain the fingerprint from the provider
and add `host_key = "SHA256:..."` to the server block. An empty value is not
needed.

## Transport

By default SVPN uses SSH camouflage and UDP. If UDP is blocked, set
`mimic = ["ssh"]` in the `transport` block. The UDP port range is the string
`udp_ports = "60000-60009"`.

`tcp_port` is a fixed TCP-fallback port. In auto mode it is optional and
ephemeral by default, so no setting is required. With `mimic = ["ssh"]` and
no UDP strategies it is required: a TCP-only server needs a known port.
`mimic` and `tcp_port` can be set per server inside its block: different VPSs
may use different camouflage sets.

## Autostart

```bash
sudo install -d -m 700 /etc/systemd/system
sudo tee /etc/systemd/system/svpn.service >/dev/null <<'EOF'
[Unit]
Description=SVPN
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/svpn multi --config /etc/svpn/vpn.hcl
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

For a single server replace `multi` with the plain invocation:
`ExecStart=/usr/local/bin/svpn --config /etc/svpn/vpn.hcl`.

## `svpn setup` details

`svpn setup --config FILE` prepares every VPS from the configuration: it
detects the environment, installs the missing approved packages (`curl`,
`tar`, `gzip`, `awk`, `ip`, `nft`, `sysctl`, CA certificates), downloads the
SVPN release from GitHub on the VPS itself and installs the binary. The
configuration is never modified; setup creates no hook files.

Supported environments: Debian 12 and Rocky 10 (GNU libc) on x86_64 and
aarch64 with hardware AES. SSH access as `root` or as a regular user with
passwordless `sudo -n`; passwords and interactive sudo are not supported.
OpenWrt, Alpine and musl are not covered.

Repeat runs and versions:

- Only the managed file `/usr/local/bin/svpn` is overwritten. The replacement
  is atomic; the report shows `partial` for a partial install.
- The client's exact version is preferred. If its release or platform archive
  is unavailable, the latest stable release with compatible control/hook
  metadata is selected and the reason is reported. A checksum failure is an
  error, never a switch to another release.
- A selected older version may replace a newer installation; setup reports
  this explicitly in a `downgrade=` field.

After installation the binary hash, mode and version are verified. Setup
never starts SVPN and never executes the hooks: it activates no routes, NAT,
DNS or firewall, creates no services and does not touch the local egress.

Hosts are processed in configuration order; one failing host does not stop
the others. Every host prints a
`SETUP host=… status=success|failed|partial|unknown|not-attempted` line with
the selected version, a `downgrade=` field and the `changed=` list. The
aggregate exit code is nonzero after any failure. Interruption (Ctrl+C,
SIGTERM) stops new hosts: the active host is reported `unknown`, the remaining
ones `not-attempted`.

## State and limits

In the foreground watch for the `serving` and `local-exit: ready` lines. With
systemd use `journalctl -u svpn -f`. Repeated runs of identical configurations
take address pairs from the `10.77.0.0/16` pool. On a conflict inspect the
used addresses with `ip addr`.

`fallback_sticky.state` stores the owners of ASN groups and sticky groups.
By default it is a path beside the geo database with a `.state.json` suffix.
State survives restarts. No snap-back is performed.

## Using only part of the features

Only sticky by names, no databases:

```hcl
server "nl" { address = "203.0.113.10" }

sticky "claude" {
  names = ["claude.ai"]
  via   = ["nl"]
  every = "5m"
}
```

Only ASN groups (automatic sticky for everything):

```hcl
geo { db = "/etc/svpn/asn.csv" }

fallback_sticky {
  strategy = "sticky-asn"
}

server "nl" { address = "203.0.113.10" }
server "de" { address = "198.51.100.20" }
```

Only a local egress by names:

```hcl
server "nl" { address = "203.0.113.10" }

sticky "home" {
  names = ["printer.lan", "nas.home"]
  via   = local
  every = "5m"
}
```

`countries` selectors need `country.db`; `asn` selectors and
`strategy = "sticky-asn"` need `geo.db`. Do not add blocks your scenario does
not need.

## Limits

- Only IPv4 is tunnelled. IPv6 is not protected by this configuration.
- DNS is not intercepted or spoofed: SVPN resolves only the names from its
  sticky blocks; the system resolver stays yours.
- A name behind a large CDN resolves into thousands of addresses shared with
  other services: the sticky group pins them too, until the records wash out.
  Use `ips` for precise cases.
- The complete Linux example uses TUN, root, `iproute2` and `nftables`.
- Client hooks do not run after `SIGKILL`. The kernel closes TUN and sockets.
  The next start must restore its routes and rules. Do not use hooks for
  irreversible changes to resources you do not own.
