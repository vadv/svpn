# SVPN: advanced configuration

The basic single-server setup is described in [README.en.md](README.en.md).
This file covers several VPSs, `local-exit`, `sticky-asn`, GeoIP databases,
hooks, transport, systemd and `svpn setup` details.

## Several VPSs and local-exit

A complete example: two VPSs, country-based selection, `local-exit` for RU and
BY, `sticky-asn` and weight-based distribution. Replace `nl.example.com` and
`de.example.com` with the servers' IPv4 addresses in the `servers` blocks
**and in the hooks**, and replace the key path.

```toml
exit-policy = "sticky-asn"
country-db = "/etc/svpn/country.csv"
geo-db = "/etc/svpn/asn.csv"
exit-state = "/etc/svpn/exits.json"
local-exits = ["RU", "BY"]

ssh-user = "root"
ssh-identity = "/full/path/to/key"
ssh-port = 22
ssh-remote-bin = "/usr/local/bin/svpn"
mimic = ["ssh"]
tcp-port = 41020
udp-port-range = "60000-60009"

# Protect the VPS addresses when the default route is replaced. This assumes
# no pre-existing host routes for these addresses.
up-command = "wan=$(ip -4 route show default | awk 'NR==1{print $5}'); gateway=$(ip -4 route show default | awk 'NR==1{print $3}'); for ip in nl.example.com de.example.com; do ip route replace \"$ip/32\" via \"$gateway\" dev \"$wan\"; done; ip route replace 0.0.0.0/1 dev \"$SVPN_TUN_NAME\"; ip route replace 128.0.0.0/1 dev \"$SVPN_TUN_NAME\""
down-command = "for ip in nl.example.com de.example.com; do ip route del \"$ip/32\" 2>/dev/null || true; done"

# These server hooks run on each VPS and at the local-exit on the client.
server-up = '''
set -e
sysctl -qw net.ipv4.ip_forward=1
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((10000 + n))
table=svpn_egress_$n
owner=/run/svpn-egress-$SVPN_SESSION_ID-$table_id
rm -f "$owner.rule" "$owner.route" "$owner.nat"
wan=$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
gateway=$(ip -4 route show default | awk 'NR==1{print $3}')
if ip -4 rule show pref "$table_id" | grep -v "from $SVPN_PEER_ADDR lookup $table_id" | grep -q .; then
    echo "svpn: policy priority $table_id is already in use" >&2
    exit 1
fi
if ip -4 route show table "$table_id" | grep -v "via $gateway dev $wan" | grep -q .; then
    echo "svpn: policy table $table_id is already in use" >&2
    exit 1
fi
if ! ip -4 rule show pref "$table_id" | grep -q "from $SVPN_PEER_ADDR lookup $table_id"; then
    ip rule add pref "$table_id" from "$SVPN_PEER_ADDR" table "$table_id"
fi
: > "$owner.rule"
ip route replace default via "$gateway" dev "$wan" table "$table_id"
: > "$owner.route"
nft delete table inet "$table" 2>/dev/null || true
nft -f - <<EOF
add table inet $table
add chain inet $table postrouting { type nat hook postrouting priority srcnat; }
add rule inet $table postrouting ip saddr $SVPN_PEER_ADDR masquerade
EOF
: > "$owner.nat"
'''
server-down = '''
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((10000 + n))
owner=/run/svpn-egress-$SVPN_SESSION_ID-$table_id
wan=$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
gateway=$(ip -4 route show default | awk 'NR==1{print $3}')
if [ -f "$owner.rule" ]; then
    ip rule del pref "$table_id" from "$SVPN_PEER_ADDR" table "$table_id" 2>/dev/null || true
    rm -f "$owner.rule"
fi
if [ -f "$owner.route" ]; then
    ip route del default via "$gateway" dev "$wan" table "$table_id" 2>/dev/null || true
    rm -f "$owner.route"
fi
if [ -f "$owner.nat" ]; then
    nft delete table inet "svpn_egress_$n" 2>/dev/null || true
    rm -f "$owner.nat"
fi
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

`weight = 3` and `weight = 1` mean a rough 3:1 distribution. With `sticky-asn`
addresses of one network keep their chosen exit while it is alive. Weights
affect owner selection, not individual packets.

## How the path is selected

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

The example `server-up` enables IPv4 forwarding and uses policy table
`10000+n`. It rejects foreign rules and tables. It does not restore the
previous forwarding value on shutdown. It assumes no pre-existing host routes
to `nl.example.com` or `de.example.com`. If you already have such routes, save
them and add restoration to your own `down-command`.

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

Country Lite determines the destination country. ASN Lite is needed for
`sticky-asn`. SVPN loads the CSV files at startup and does not re-read them
live. Update the files and restart the service:

```bash
sudo systemctl restart svpn
```

For ASN there is `scripts/update-asn-db.sh` in the source tree. It downloads
a new database, validates it and keeps the previous one as `asn.csv.prev`.

## Server hooks

`server-up` and `server-down` run on the VPS and at `local-exit` on the
client. The ready-made scripts are shipped in the release archive and are
installed by `svpn setup` into `/usr/local/lib/svpn/`. For a manual install
take them from the archive.

Hooks receive these environment variables:

- `SVPN_EVENT` — `up` or `down`;
- `SVPN_TUN_NAME` — the TUN name;
- `SVPN_TUN_ADDR` — this side's tunnel address;
- `SVPN_PEER_ADDR` — the other side's tunnel address;
- `SVPN_SESSION_ID` — the process PID.

The timeout is 10 seconds. A failing `up` prevents the session from starting;
a failing `down` is only logged. Example scripts are shown in the
configuration above.

## Client hooks

Client-side commands are configured with:

- `up-command` and `down-command` — a string for `/bin/sh -c`;
- `up-script` and `down-script` — a path to an executable file.

Only one variant per direction may be set. Commands receive the same variables
as server hooks and share the same 10-second timeout. The example in the quick
start sends all IPv4 into the tunnel and keeps a direct route to the VPS. With
several servers add a route for each of them.

## SSH checks and host keys

The client needs a private key, and its public part must be authorized on the
VPS. Use an absolute key path. If the key is passphrase-protected, load it into
`ssh-agent` first.

Without `ssh-host-key` SVPN uses TOFU and stores the fingerprint in its
known-hosts file. For strict checking obtain the fingerprint from the provider
and add `ssh-host-key = "SHA256:..."` to each server. An empty value is not
needed.

## Transport

By default SVPN uses SSH camouflage and UDP. If UDP is blocked, set
`mimic = ["ssh"]` and `tcp-port = 41020`. The UDP port range is set with
`udp-port-range = "60000-60009"`.

## Autostart

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

For a single server replace `multi` with the plain invocation:
`ExecStart=/usr/local/bin/svpn --config /etc/svpn/vpn.toml`.

## `svpn setup` details

`svpn setup --config FILE` prepares every VPS from the configuration: it
detects the environment, installs the missing approved packages (`curl`, `tar`,
`gzip`, `awk`, `ip`, `nft`, `sysctl`, CA certificates), downloads the SVPN
release from GitHub on the VPS itself and installs
`server-up`/`server-down`. The configuration is never modified.

Supported environments: Debian 12 and Rocky 10 (GNU libc) on x86_64 and
aarch64 with hardware AES. SSH access as `root` or as a regular user with
passwordless `sudo -n`; passwords and interactive sudo are not supported.
OpenWrt, Alpine and musl are not covered.

Repeat runs and versions:

- Only the managed files are overwritten: `/usr/local/bin/svpn`,
  `/usr/local/lib/svpn/server-up`, `/usr/local/lib/svpn/server-down`.
  Each replacement is atomic; the set as a whole is not, and the report shows
  `partial`.
- The client's exact version is preferred. If its release or platform archive
  is unavailable, the latest stable release with compatible control/hook
  metadata is selected and the reason is reported. A checksum failure is an
  error, never a switch to another release.
- A selected older version may replace a newer installation; setup reports
  this explicitly in a `downgrade=` field.

After installation the hashes, modes and the binary version are verified.
Setup never starts SVPN and never executes the hooks: it activates no routes,
NAT, DNS or firewall, creates no services and does not touch local-exit. The
hook paths must already be present in the client configuration — setup does
not add them.

Hosts are processed in configuration order; one failing host does not stop the
others. Every host prints a
`SETUP host=… status=success|failed|partial|unknown|not-attempted` line with
the selected version, a `downgrade=` field and the `changed=` list. The
aggregate exit code is nonzero after any failure. Interruption (Ctrl+C,
SIGTERM) stops new hosts: the active host is reported `unknown`, the remaining
ones `not-attempted`.

## State and limits

In the foreground watch for the `serving` and `local-exit: ready` lines. With
systemd use `journalctl -u svpn -f`. Repeated runs of identical configurations
take address pairs from the `10.77.0.0/16` pool. On a conflict inspect the used
addresses with `ip addr`.

`exit-state` stores the selected ASN owners. By default it is a path next to
`geo-db` with a `.state.json` suffix. State survives restarts. No snap-back is
performed.

## Using only part of the features

Sticky ASN without `local-exit`:

```toml
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
```

Country selection without `local-exit`:

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
`multi` and `geo-db`. Do not add fields your scenario does not need.

## Limits

- Only IPv4 is tunnelled. IPv6 is not protected by this configuration.
- DNS is not changed automatically. Choose DNS separately.
- Country and ASN databases do not classify domains. The decision is made by
  destination IP after name resolution.
- The complete Linux example uses TUN, root, `iproute2` and `nftables`.
- Client hooks do not run after `SIGKILL`. The kernel closes TUN and sockets.
  The next start must restore its routes and rules. Do not use hooks for
  irreversible changes to resources you do not own.
