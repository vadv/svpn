# SVPN

[Русский](README.md)

SVPN is an encrypted IPv4 tunnel to a Linux server you control. The whole
server side is one binary: no daemon, no certificates, no config file. The
client starts it over SSH when you connect, and it exits when the session
ends. The only server preparation is plain Linux routing — IP forwarding and
a masquerade rule, the same two steps every VPN needs.

On the wire the tunnel passes for QUIC, WebRTC or mosh traffic, or for random
bytes. At connect time all candidates race, and the first working one wins.
Where UDP is blocked, a TCP fallback disguised as SSH takes over.

Hooks on the client shape the routing: from a single test address up to a
split VPN where Russian sites go direct and the rest of the world goes
through the tunnel (ready-made scripts below).

The quick start runs both processes **as root** and routes **only 1.1.1.1**
through the tunnel, so you can verify the whole path before trusting it with
real traffic.

## Requirements

- A CPU with AES-NI (x86-64) or ARMv8 crypto extensions.
- Server: Linux with a TUN device, reachable by SSH key as root.
- Client: Linux or macOS.

## 1. Install a prebuilt binary

Download the archive for your system and its `.sha256` from
[Releases](https://github.com/vadv/svpn/releases):

- `linux-x86_64-gnu` — Linux server and client (glibc 2.36+: Debian 12,
  Ubuntu 24.04 or newer)
- `openwrt-aarch64` — OpenWrt ARM64 router client
- `macos-arm64` — macOS client on Apple Silicon

Verify the checksum and install (on macOS use `shasum -a 256 -c`):

```sh
sha256sum -c svpn-*.tar.gz.sha256
tar -xzf svpn-*.tar.gz
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

On OpenWrt, as root: `tar -xzf svpn-*.tar.gz && cp svpn /usr/bin/svpn`.

## 2. Prepare the server (once)

Run **as root on a fresh Debian/Ubuntu server without UFW or firewalld**. Use
either the iptables commands here or the nftables equivalent at the end of
this step, not both. Both add rules without flushing existing chains or
changing their policies:

```sh
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent

printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-svpn.conf
sysctl -p /etc/sysctl.d/90-svpn.conf

iptables -I INPUT -p udp --dport 60000:60009 -j ACCEPT
iptables -I INPUT -p tcp --dport 41020 -j ACCEPT
iptables -I INPUT -i svpn0 -d 10.77.0.1 -p icmp --icmp-type echo-request -j ACCEPT
iptables -I FORWARD -i svpn0 -s 10.77.0.0/24 -j ACCEPT
iptables -I FORWARD -o svpn0 -d 10.77.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o svpn0 -j MASQUERADE

netfilter-persistent save
systemctl enable netfilter-persistent
```

This enables forwarding, accepts traffic from the tunnel, and masquerades VPN
clients behind the server's outgoing address. The settings survive a reboot.
If your VPS also has a provider firewall, open UDP 60000–60009 and TCP 41020
there as well.

**Using nftables instead of iptables?** Run this equivalent (the sysctl step
is the same):

```sh
nft add table inet svpn
nft 'add chain inet svpn input { type filter hook input priority -10; policy accept; }'
nft add rule inet svpn input udp dport 60000-60009 accept
nft add rule inet svpn input tcp dport 41020 accept
nft add rule inet svpn input iifname "svpn0" ip daddr 10.77.0.1 icmp type echo-request accept
nft 'add chain inet svpn forward { type filter hook forward priority -10; policy accept; }'
nft add rule inet svpn forward iifname "svpn0" ip saddr 10.77.0.0/24 accept
nft add rule inet svpn forward oifname "svpn0" ip daddr 10.77.0.0/24 ct state established,related accept
nft add table ip svpn-nat
nft 'add chain ip svpn-nat postrouting { type nat hook postrouting priority 100; }'
nft 'add rule ip svpn-nat postrouting ip saddr 10.77.0.0/24 oifname != "svpn0" masquerade'
```

Persist it by snapshotting the live ruleset (your existing tables are kept):

```sh
echo 'flush ruleset' > /etc/nftables.conf
nft list ruleset >> /etc/nftables.conf
systemctl enable --now nftables
```

One catch: unlike iptables, nftables runs every base chain on a hook, so an
`accept` in the svpn table cannot save a packet from another chain's `drop`
policy. If your existing input or forward chain drops by default, add the
accept rules to that chain instead of creating the svpn table.

You never run the server by hand — the client starts it over SSH.

## 3. Write the client config

Save as `vpn.toml`, replacing the server address and key path:

```toml
server = "vpn.example.com"
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519.pub"
peer-tun-name = "svpn0"
tcp-port = 41020
up-command = 'ip route add 1.1.1.1/32 dev "$SVPN_TUN_NAME" src "$SVPN_TUN_ADDR"'
down-command = 'ip route del 1.1.1.1/32 dev "$SVPN_TUN_NAME"'
```

On **macOS**, replace the two hook lines with:

```toml
up-command = 'route -n add -host 1.1.1.1 -interface "$SVPN_TUN_NAME"'
down-command = '''
if route -n get -host 1.1.1.1 | grep -q "interface: $SVPN_TUN_NAME$"; then
    route -n delete -host 1.1.1.1 -interface "$SVPN_TUN_NAME"
fi
'''
```

Hooks are ordinary shell commands that run **on the client** through
`/bin/sh -c`: `up-command` after the tunnel interface is configured,
`down-command` before it closes. SVPN tells them the real interface name in
`SVPN_TUN_NAME` (plus `SVPN_TUN_ADDR`, `SVPN_PEER_ADDR`, `SVPN_EVENT`), so you
never have to guess `utunN`. Hooks get 10 seconds. A failing `up-command`
aborts the connection and still runs the down hook for cleanup. For executable
files instead of inline commands, use `up-script` / `down-script`.

`tcp-port` pins the TCP fallback to the port you opened in step 2. Without it
the fallback picks an ephemeral port that your firewall will most likely drop.

## 4. Run

Load your private key into an SSH agent — the `.pub` path in the config picks
the matching agent key — then start the client:

```sh
eval "$(ssh-agent -s)"
ssh-add /path/to/id_ed25519
ssh root@vpn.example.com /usr/local/bin/svpn --version
sudo env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" /usr/local/bin/svpn --config vpn.toml
```

In another terminal:

```sh
ping -c 3 1.1.1.1
```

Replies mean the tunnel works end to end. Stop with **Ctrl+C** — the down hook
removes the test route. To route other destinations, edit the route in both
hooks. To tunnel only non-RU traffic or all of it, see the next two sections.

The first SSH host key is trusted on first use. To verify the very first
connection, set `ssh-host-key = "SHA256:…"` from a fingerprint you trust.

## Split VPN: RU direct, the world through the tunnel (Linux)

Russian sites go direct. All other traffic leaves through the tunnel.

How it works. Routing table 100 holds the RU subnets via the normal gateway
and a default route via the tunnel. Rule 100 sends all traffic to this table.
Rule 99 serves local networks first, so LAN traffic never enters the tunnel.
The RU subnet list (about 9000 networks) is downloaded from ipdeny once and
cached in `/etc/svpn-ru.zone`.

You do not write any server address by hand: the script reads them from the
client's open SSH connections. When the tunnel dies, traffic goes direct
(fail-open). IPv6 never enters the tunnel.

You need iproute2 and curl. Save both scripts next to `vpn.toml`
(`chmod +x`) and reference them with `up-script = "geo-up.sh"` and
`down-script = "geo-down.sh"`.

`geo-up.sh`:

```sh
#!/bin/sh
set -e

TABLE=100
ZONE=/tmp/svpn-ru.zone
CACHE=/etc/svpn-ru.zone
URL=https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone

valid() {
    awk '/^[[:space:]]*(#|$)/ { next }
        { if ($0 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) bad = 1
          split($0, a, /[.\/]/)
          for (i = 1; i <= 4; i++) if (a[i] > 255) bad = 1
          if (a[5] > 32) bad = 1
          n++ }
        END { exit (bad || n < 100) ? 1 : 0 }' "$1" 2>/dev/null
}

if ! valid "$ZONE"; then
    if curl -fsS -m 8 -o "$ZONE.new" "$URL" && valid "$ZONE.new"; then
        mv "$ZONE.new" "$ZONE"
        cp "$ZONE" "$CACHE"
    elif valid "$CACHE"; then
        cp "$CACHE" "$ZONE"
    else
        echo "svpn georoute: no valid RU zone" >&2
        exit 1
    fi
    rm -f "$ZONE.new"
fi

GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')

ip rule del priority 99 2>/dev/null || true
ip rule del priority 100 2>/dev/null || true
ip rule add priority 99 table main suppress_prefixlength 0
ip rule add priority 100 table "$TABLE"

awk -v gw="$GW" -v dev="$DEV" -v t="$TABLE" \
    '/^[0-9]/ { printf "route replace %s via %s dev %s table %s\n", $1, gw, dev, t }' \
    "$ZONE" | ip -batch -

ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | \
    grep -E '^[0-9.]+$' | sort -u | \
    while read -r ip; do
        ip route replace "$ip" via "$GW" dev "$DEV" table "$TABLE"
    done

ip route replace default dev "$SVPN_TUN_NAME" table "$TABLE"
```

`geo-down.sh`:

```sh
#!/bin/sh
ip rule del priority 99 2>/dev/null
ip rule del priority 100 2>/dev/null
ip route flush table 100 2>/dev/null
exit 0
```

The first start downloads the zone, later starts reuse the file. To refresh
the RU list, remove `/tmp/svpn-ru.zone` and restart the client. DNS follows
the same split by itself: a LAN resolver goes direct, a public non-RU
resolver goes through the tunnel. For fail-closed (no tunnel, no internet),
append `ip route replace unreachable default table 100 metric 4278198272` to
`geo-up.sh`. In `multi`, a server that has not connected yet when the hook
runs may later transport itself through the tunnel: it works, just slower.

## Route all traffic

To send everything through the tunnel, point the default route at it and pin
direct routes to the servers, or the tunnel will carry its own transport.
Instead of replacing the default route, add two /1 routes that outrank it.
The rest of the system never notices.

You do not write any server address by hand. The script reads the addresses
from the client's open SSH connections (`ss` on Linux, `lsof` on macOS) and
stores them in `/tmp/svpn-direct`, where the down hook finds them.

These hooks are multi-line, so save them as executable files (`chmod +x`)
next to `vpn.toml` and reference them with `up-script = "up.sh"` and
`down-script = "down.sh"`.

Linux `up.sh`:

```sh
#!/bin/sh
set -e
GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')
ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | \
    grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do
    ip route replace "$ip" via "$GW" dev "$DEV"
done < /tmp/svpn-direct
ip route add 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route add 128.0.0.0/1 dev "$SVPN_TUN_NAME"
```

Linux `down.sh`:

```sh
#!/bin/sh
ip route del 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route del 128.0.0.0/1 dev "$SVPN_TUN_NAME"
while read -r ip; do
    ip route del "$ip" 2>/dev/null || true
done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
```

macOS `up.sh`:

```sh
#!/bin/sh
set -e
GW=$(route -n get default | awk '/gateway/ {print $2}')
lsof -nP -iTCP -a -c svpn 2>/dev/null | awk -F'->' 'NF > 1 { split($2, a, ":"); print a[1] }' | \
    grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do
    route -n add -host "$ip" "$GW"
done < /tmp/svpn-direct
route -n add -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n add -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
```

macOS `down.sh`:

```sh
#!/bin/sh
route -n delete -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n delete -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
while read -r ip; do
    route -n delete -host "$ip" 2>/dev/null || true
done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
```

The server needs nothing new: the masquerade from step 2 already covers the
whole tunnel subnet. Traffic to the servers' public IPs goes direct, outside
the tunnel. SVPN does not touch DNS, so make sure your resolver is not the
router's LAN address, or queries will bypass the tunnel. IPv6 never enters
the tunnel: disable it on the client if leaking it matters.

## Choosing a mimic

`mimic` selects what the data channel looks like on the wire. The default, no
`mimic` at all, is **auto**: the four UDP candidates and the TCP fallback with
`ssh` camouflage all start at the same time. SVPN pings the server through
each of them. The first reply wins, and the other candidates close. Start with
auto. Pin a list only when you know your network.

| Value    | Looks like                                          | Use when |
|----------|-----------------------------------------------------|----------|
| `quic`   | HTTP/3 traffic (real QUIC/TLS 1.3, CONNECT-UDP)     | the everyday choice, blends in with ordinary web traffic |
| `webrtc` | a WebRTC call (real ICE/DTLS/SCTP)                  | QUIC is throttled or blocked but calls pass |
| `mosh`   | mosh remote-terminal UDP                            | you want small, sparse datagrams like an interactive shell |
| `obfs`   | uniformly random bytes                              | any recognizable protocol signature is unwanted |
| `ssh`    | a full SSH handshake over TCP                       | UDP is blocked entirely (requires `tcp-port`) |
| `banner` | a single SSH greeting line over TCP                 | TCP-only with minimal ceremony (requires `tcp-port`) |
| `none`   | plain TCP                                           | debugging only (requires `tcp-port`) |

The race repeats only after the winner fails. A failure means five seconds
without data on the channel or a broken transport. After a failure, all
candidates start at the same time again. When no candidate works, the race
repeats after 1, 2, 4, 8 and 16 seconds, and then every 30 seconds.

The winner stays in use until it fails. SVPN does not check whether another
candidate has become faster.

In auto, a candidate that cannot prepare its channel is excluded until the end
of the SSH session. When every candidate is excluded, the connection to the
server closes.

Open connections do not move to the new channel. TCP connections receive a
reset, and UDP streams are removed. Applications open new connections through
the new channel.

To race only specific candidates, set a fixed list: `mimic = ['quic', 'mosh']`
in the config or repeated `--mimic` flags on the CLI. A TCP-only list such as
`mimic = ['ssh']` requires `tcp-port`. In fixed mode candidates are never
excluded. A candidate that cannot prepare its channel waits 30 seconds and
tries again.

Camouflage makes the wire format resemble the named protocol. Whether it
defeats a particular filter is an open question, so measure with `svpn perf`
instead of assuming.

## Limits

- IPv4 only: SVPN neither carries nor protects IPv6, and does not touch DNS.
- Fragmented IPv4 packets are dropped. The default MTU is 1280.
- A LAN behind the client needs SNAT to the client's tunnel address
  (`10.77.0.2`) before its packets enter the tunnel.
- `svpn serve` refuses to run outside an SSH session.

## Running the client without root (Linux)

```sh
sudo setcap cap_net_admin=ep /usr/local/bin/svpn
```

This lets SVPN create and configure the tunnel interface without root. It does
not extend those rights to the hooks: route commands like the ones above need
their own privileges. Repeat `setcap` after replacing the binary.

## More

- `svpn multi --help` — a pool of servers with weights and per-server
  overrides (`[[servers]]` in TOML).
- `svpn perf --help` — an iperf3-style speed test through the tunnel (the
  server listens on port 5201 inside the tunnel).
- `svpn --help` — every CLI flag mirrors a TOML key. A config file and CLI
  settings are mutually exclusive.

## Development

Build with Cargo only for development. Install Rust 1.89+ and a C compiler:

```sh
cargo build --locked
cargo test --locked --workspace
```

See [build/README.md](build/README.md) for release build recipes.

## License

MIT — see [LICENSE](LICENSE). Dependency licenses are in
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
