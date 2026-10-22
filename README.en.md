# SVPN

[Русский](README.md)

SVPN is an encrypted IPv4 tunnel to a Linux server you control. The server
side is the same binary: the client launches it over SSH, and it lives only
as long as the connection does. No daemon, no certificates, no server-side
config. On the wire the tunnel looks like QUIC, WebRTC, or mosh — and where
UDP is blocked, like SSH over TCP.

## What you get

- **The server is one file.** Copy `svpn` to a server, add its address to the
  client TOML — it is in the pool. No daemon, no config, no state on the
  server: the process is launched by your SSH session and dies with it.
- **One interface, as many servers as you want.** The pool hides behind a
  single TUN on the client. A new server is three lines of config, not a new
  VPN.
- **Weights instead of a balancer.** A server's `weight` sets its share of
  new connections.
- **A dead server is routine, not an outage.** Each server is a state machine:
  connecting, ready, checking, backoff. Five seconds of silence takes it out
  of the pool, traffic moves to the living ones, and the dead one restarts
  itself (1→2→4…→60 s). The VPN stops only when no server is left alive.
- **Camouflage picked for your network.** `auto` tries transports from fast
  to survivable — QUIC → WebRTC → obfs → mosh → SSH/TCP — and sticks with the
  first one that actually works. The choice does not freeze: about every
  10 minutes a background probe compares transports by latency and loss, and
  a clearly faster one takes over new connections.

```text
┌─────────────────┐        ┌──────────┐
│ client: one TUN │───────▶│ server A │  weight 3 — carries traffic
│                 │───────▶│ server B │  weight 1 — carries traffic
│                 │────╳   │ server C │  down — restarts itself
└─────────────────┘        └──────────┘
    C is down — the VPN is fine: new connections go to A and B
```

## Requirements

- Server: Linux with TUN and nftables (Debian 12 / Ubuntu 24.04 out of the
  box), root login over an SSH key, no UFW/firewalld.
- Client: Linux or macOS, CPU with AES-NI or ARMv8 crypto.

## 1. Install svpn

Download the archive and its `.sha256` from
[Releases](https://github.com/vadv/svpn/releases) **on the server and on the
client** — it is the same file:

- `linux-x86_64-gnu` — Linux server and client (glibc 2.36+)
- `openwrt-aarch64` — client on an OpenWrt ARM64 router (`cp svpn /usr/bin/svpn`)
- `macos-arm64` — macOS client on Apple Silicon (checksum: `shasum -a 256 -c`)

```sh
sha256sum -c svpn-*.tar.gz.sha256
tar -xzf svpn-*.tar.gz
sudo install -m 755 svpn /usr/local/bin/svpn
```

The client launches the server at the path `/usr/local/bin/svpn`
(change with the `ssh-remote-bin` key). Nothing else to configure on the
server: routing is enabled by the server hook in the config below.

## 2. Write vpn.toml and run

Create a file named `vpn.toml` and fill in your server address and the path
to your key:

```toml
server = "vpn.example.com"
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519"
tcp-port = 41020

# All traffic goes through the tunnel: two /1 routes override the default
# route. Routes to the servers themselves stay direct — they carry the
# tunnel's own traffic. The hook finds server addresses via the client's
# open SSH connections (Linux).
up-command = '''
GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')
ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do ip route replace "$ip" via "$GW" dev "$DEV"; done < /tmp/svpn-direct
ip route add 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route add 128.0.0.0/1 dev "$SVPN_TUN_NAME"
'''
down-command = '''
ip route del 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route del 128.0.0.0/1 dev "$SVPN_TUN_NAME"
while read -r ip; do ip route del "$ip" 2>/dev/null || true; done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
'''

# Runs ON THE SERVER: enables forwarding and masquerades tunnel clients.
server-up = '''
sysctl -q net.ipv4.ip_forward=1 || exit 1
EGRESS=$(ip -4 route show default | awk '{print $5; exit}')
nft -f - <<NFT
table ip svpn { set peers { type ipv4_addr; } chain post { type nat hook postrouting priority srcnat; policy accept; } }
flush chain ip svpn post
add rule ip svpn post ip saddr @peers oifname "$EGRESS" masquerade
NFT
nft add element ip svpn peers "{ $SVPN_PEER_ADDR }"
'''
server-down = 'nft delete element ip svpn peers "{ $SVPN_PEER_ADDR }" || true'
```

Run:

```sh
sudo svpn --config vpn.toml
```

If `ssh-identity` is omitted, the keys come from ssh-agent (this also covers
passphrase-protected keys) — run with `sudo -E` so sudo can see the agent.

In another terminal:

```sh
ping -c 3 1.1.1.1
```

Replies mean all traffic already goes through the server. **Ctrl+C** stops it: the down hooks remove the routes on
the client and the masquerade on the server. To send only non-RU traffic
through the tunnel, see "Routing scenarios" below.

What happens on startup: the client opens an SSH session and runs
`svpn serve` on the server. The server creates its TUN and runs `server-up`,
returning the exit code and output. A failure aborts the connection
immediately, before the client TUN is created. Then the transport candidates
race, the first responder wins, and data flows.

If your VPS has a firewall in the provider panel, open UDP 60000–60009 and
TCP 41020.

The TUN name and tunnel addresses are assigned automatically: the kernel
picks a free name (tun0, utun4, …) and the addresses come from the
10.77.0.0/16 pool — hooks see the actual values in $SVPN_TUN_NAME,
$SVPN_TUN_ADDR and $SVPN_PEER_ADDR. To pin them: `peer-tun-name = "svpn0"`,
and the addresses as a `tun-addr` + `peer-addr` pair (only together).

## 3. Multiple servers

A weighted server pool — the `multi` command and `[[servers]]` sections in
the same TOML. Server fields override the root ones for that server only:

```toml
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519"
tcp-port = 41020
# up-command / down-command / server-up / server-down — as in step 2.
# Root server-up and server-down apply to every server.

[[servers]]
address = "a.example.com"
weight = 3

[[servers]]
address = "b.example.com"
weight = 1
server-up = "..."     # a custom variant for b only
```

```sh
sudo env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" /usr/local/bin/svpn multi --config vpn.toml
```

A lost server is restarted with backoff, its TCP flows are reset, and traffic
moves to the remaining servers. The client TUN is created once the first
server is ready.

## Hooks in detail

All hooks are shell commands run via `/bin/sh -c`, limited to 10 seconds. For
executable files instead of strings use `up-script` / `down-script` (paths
are relative to the config directory).

**Client** `up-command` / `down-command`: after the client TUN is configured
and before it is closed. Environment: `SVPN_TUN_NAME`, `SVPN_TUN_ADDR`,
`SVPN_PEER_ADDR`, `SVPN_EVENT`. An `up-command` failure aborts the
connection. `down-command` still runs.

**Server** `server-up` / `server-down`: after the server TUN is up and before
the server process exits. Environment: `SVPN_PEER_ADDR` (client tunnel
address) plus the same `SVPN_*` set. Command length is limited to 1500
characters. The server returns the exit code and up to 600 bytes of
stdout/stderr — enough for diagnostics. Write real logs to a file on the
server. A `server-up` failure aborts the connection before the client TUN is
created.

## Choosing a mimic

By default **auto** is active: four UDP candidates and TCP with `ssh`
camouflage start simultaneously, the server is pinged through each, and the
first responder wins. Start with auto. Pin a list only when you know your
network: `mimic = ['quic', 'mosh']` in TOML or repeated `--mimic` on the CLI.

Auto does not stick to the first winner. About every 10 minutes
(`remeasure-interval`), and whenever the current channel degrades,
alternatives are measured in the background. A candidate that beats the
incumbent's p90 by at least 20% and 5 ms with no more than 1/10 loss, two
measurements in a row, takes over new connections. Existing connections live
out their lives on the old channel.

| Value    | Looks like | Choose when |
|----------|------------|-------------|
| `quic`   | HTTP/3 (real QUIC/TLS 1.3, CONNECT-UDP) | everyday choice |
| `webrtc` | a WebRTC video call (ICE/DTLS/SCTP) | QUIC is throttled, calls pass |
| `mosh`   | mosh remote-terminal UDP | small infrequent datagrams |
| `obfs`   | uniformly random bytes | any protocol signature is unwanted |
| `ssh`    | full SSH handshake over TCP | UDP fully blocked (needs `tcp-port`) |
| `banner` | an SSH greeting line over TCP | TCP, minimal ceremony |
| `none`   | plain TCP | debugging only |

The winner runs until it fails (5 seconds without data or a transport
break), then the race repeats. On a total failure it retries after 1, 2, 4,
8, 16, and then every 30 seconds. A candidate that cannot prepare its
channel rests: banned for 10 minutes, doubling to 2 hours on repeat
(with ±20% jitter), then eligible for the race again. Open connections are
not moved to the new channel: TCP gets a RST and applications reconnect.

Camouflage reproduces the protocol format on the wire but does not guarantee
passing a particular filter — measure with `svpn perf`.

## Server firewall without hooks

If server hooks do not fit, configure the server once by hand as root
(iptables — the nftables equivalent is in the `server-up` example above):

```sh
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-svpn.conf
sysctl -p /etc/sysctl.d/90-svpn.conf

iptables -I INPUT -p udp --dport 60000:60009 -j ACCEPT
iptables -I INPUT -p tcp --dport 41020 -j ACCEPT
iptables -I FORWARD -i svpn0 -s 10.77.0.0/24 -j ACCEPT
iptables -I FORWARD -o svpn0 -d 10.77.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o svpn0 -j MASQUERADE
```

Persist with `iptables-persistent` to survive reboots. The server is never
started by hand — the client launches it over SSH.

## Limitations

- IPv4 only: IPv6 is neither carried nor protected — disable it on the
  client if leakage matters.
- SVPN does not change DNS: if your resolver is the router's LAN address,
  queries will bypass the tunnel.
- Fragmented IPv4 packets are dropped. Default MTU is 1280.
- A LAN behind the client needs SNAT to the client tunnel address
  (`10.77.0.2`).
- The server's SSH key is remembered on first connect. Pin it explicitly with
  `ssh-host-key = "SHA256:…"`.
- `svpn serve` refuses to run outside an SSH session.

## Running the client without root (Linux)

```sh
sudo setcap cap_net_admin=ep /usr/local/bin/svpn
```

The capability does not extend to hooks: routing commands need their own
privileges. Re-run `setcap` after replacing the binary.

## Routing scenarios

A ready-made hook set for split VPN: RU sites direct, the rest of the world
through the tunnel.

### RU direct, world via VPN (Linux)

Table 100 holds RU subnets via the regular gateway and a default route via
the tunnel. Rule 100 sends all traffic there, rule 99 serves local networks
first. The subnet list (~9000 networks) is downloaded from ipdeny once and
cached in `/etc/svpn-ru.zone`. The script reads server addresses from the
client's open SSH connections. Tunnel down — traffic goes direct (fail-open).

Requires iproute2 and curl. Save both scripts next to `vpn.toml`
(`chmod +x`) and hook them up: `up-script = "geo-up.sh"`,
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
    '/^[0-9]/ { printf "route replace %s via %s dev %s table %s\n", $1, gw, dev, t }' "$ZONE" | ip -batch -

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

To refresh the RU list, delete `/tmp/svpn-ru.zone` and restart the client.
For fail-closed (no tunnel — no internet) append to `geo-up.sh`:
`ip route replace unreachable default table 100 metric 4278198272`. In
`multi`, a server that missed the up hook may later carry its transport
through the tunnel: it works, just slower.

The masquerade from the server hook already covers the whole tunnel subnet,
and the /1 routes plus direct server routes are in the step-2 hooks.

### Full tunnel on macOS

Client up/down for macOS (server hooks are the same as in step 2):

```toml
up-command = '''
GW=$(route -n get default | awk '/gateway/ {print $2}')
lsof -nP -iTCP -a -c svpn 2>/dev/null | awk -F'->' 'NF > 1 { split($2, a, ":"); print a[1] }' | grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do route -n add -host "$ip" "$GW"; done < /tmp/svpn-direct
route -n add -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n add -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
'''
down-command = '''
route -n delete -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME" 2>/dev/null
route -n delete -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME" 2>/dev/null
if [ -f /tmp/svpn-direct ]; then
    while read -r ip; do route -n delete -host "$ip" 2>/dev/null || true; done < /tmp/svpn-direct
    rm -f /tmp/svpn-direct
fi
'''
```

## Further reading

- `svpn perf --help` — iperf3-style throughput measurement through the tunnel.
- `svpn multi --help` — server pool, `[[servers]]` in TOML.
- `svpn --help` — every CLI flag mirrors a TOML key. Config file and CLI
  settings are mutually exclusive.

## Development

Install Rust 1.89+ and a C compiler:

```sh
cargo build --locked
cargo test --locked --workspace
```

## License

MIT — see [LICENSE](LICENSE). Dependency licenses are in
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
