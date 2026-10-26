# LocalExit

LocalExit sends home-country traffic through a second, local SVPN server path.
It is a packet path, not a TCP proxy:

```text
application → client TUN → Hub → in-memory session → local serve TUN
            → host forwarding/conntrack/NAT → default route
```

The client keeps its TCP/UDP/ICMP endpoints in the host kernel. LocalExit does
not accept application connections or open replacement connections to the
destination. The control channel is an in-memory duplex. Packet framing reuses the existing
local TCP transport on `127.0.0.1:0`; there is no SSH or externally visible
listener and no application TCP termination.

The primary and local TUNs use different inner addresses, claimed from the
SVPN address pool for the lifetime of the local session. The local session
performs fixed 1:1 address translation at that boundary; kernel conntrack still
owns the external NAT state. The LocalExit source address must not be assigned
as a host-local address on either TUN or another interface.

## Requirements

LocalExit requires all of the following on the machine running the client:

- IPv4 forwarding enabled;
- a route for return traffic to the local-exit inner subnet, or source NAT;
- source NAT on the physical uplink when the inner subnet is not routable;
- a source-scoped egress rule so LocalExit packets do not follow the primary
  SVPN split-default routes back into the primary TUN;
- permission to create the second TUN and run the configured egress hooks;
- a usable IPv4 default route and physical uplink.

The normal SVPN client TUN and remote server requirements are unchanged. IPv6,
loopback and host-local/internal addresses are not LocalExit traffic. Private
destinations follow the Country DB and the administrator's routing policy.

SVPN does not replace the host firewall or silently change global forwarding
sysctls. Configure egress beforehand, or use the existing `--server-up` and
`--server-down` hooks. Those hooks run for the local serve as well as remote
serves; make their commands suitable for the machine on which they run.

## Linux example

This example uses the local-exit peer address supplied by SVPN and `eth0` as
the physical uplink. `--server-up` hooks receive `SVPN_TUN_NAME`,
`SVPN_TUN_ADDR` and `SVPN_PEER_ADDR`; use the peer as the translated source
and the TUN name for ingress matching. Replace `eth0` with the actual uplink.
Do not flush an existing firewall.

```sh
sysctl -w net.ipv4.ip_forward=1

# Choose an unused policy-table number and rule priority.
ip rule add pref 100 from "$SVPN_PEER_ADDR" table 100
# Use the physical default gateway here, not the primary SVPN TUN.
ip route replace default via 192.0.2.1 dev eth0 table 100

nft add table inet svpn_local_exit
nft 'add chain inet svpn_local_exit forward { type filter hook forward priority filter; policy accept; }'
nft add rule inet svpn_local_exit forward iifname "$SVPN_TUN_NAME" ip saddr "$SVPN_PEER_ADDR" oifname eth0 accept
nft add rule inet svpn_local_exit forward ip daddr "$SVPN_PEER_ADDR" ct state established,related accept
nft 'add chain inet svpn_local_exit postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft add rule inet svpn_local_exit postrouting iifname "$SVPN_TUN_NAME" ip saddr "$SVPN_PEER_ADDR" oifname eth0 masquerade
```

The same rules can be installed by an idempotent `--server-up` hook. A hook
used for both local and remote serves must discover the local uplink instead
of assuming `eth0`. For concurrent local exits, use a separately owned policy
and NAT table per claimed inner pair and reconcile them on restart.

For a manually managed setup, remove only the owned table on shutdown:

```sh
ip rule del pref 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
nft delete table inet svpn_local_exit
```

LocalExit owns a `/32` return route for its peer on the second TUN (this must
be explicit on macOS). A routable inner subnet needs the corresponding return
route instead of MASQUERADE. Do not use both approaches for the same traffic.

## macOS

Enable IPv4 forwarding and add an equivalent PF NAT/forwarding configuration:

```sh
sysctl -w net.inet.ip.forwarding=1
```

The PF rules must translate the local-exit inner subnet on the physical
uplink, permit return traffic, and use one source-scoped `route-to` rule so
LocalExit egress cannot follow the primary SVPN routes. Install them through
the existing PF anchors/ruleset; do not replace the host's rules with
`pfctl -f`. The exact anchor names, gateway and interface are host-specific.

## Shutdown and crashes

A normal shutdown closes both TUNs and runs the configured down hooks. On
`SIGKILL`, the kernel closes the TUN descriptors, so the interfaces disappear;
userspace session state and local NAT mappings disappear with the process.
Existing application connections are still lost.

Down hooks and firewall/sysctl restoration do not run on `SIGKILL`. Therefore
up hooks must be idempotent and must reconcile their own table/rules on the
next start. Any manually installed forwarding or firewall state remains the
administrator's responsibility until cleaned up.

The required crash checks are: both TUNs disappear, no LocalExit process or
listener remains, the next start can reuse the same inner pair, and traffic
without SVPN follows the host's ordinary routing policy.
