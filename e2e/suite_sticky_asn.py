"""Sticky-asn group: destination pinning, balance regression, failover and restart restore."""

import ipaddress
import json
import pathlib
import re
import socket

from _lib import (
    CLIENT_POOL,
    PEER,
    SERVER,
    SERVER2,
    cleanup_verified,
    command,
    session,
    ssh,
    ssh_to,
    tcp_echo,
    until,
)

HOSTS = (SERVER, SERVER2)
CSV = pathlib.Path("/tmp/e2e-asn.csv")
COUNTRY_CSV = pathlib.Path("/tmp/e2e-country.csv")
STATE = pathlib.Path("/var/lib/svpn/exit-state.json")
TARGET = "172.30.77.4"
# One /17 block per row: 131072 synthetic rows pass Geo::load's 100k-row floor and give
# every subnet a distinct ASN, so rendezvous picks differ across destination groups.
HOST_BITS = 15
ROWS = 1 << (32 - HOST_BITS)
FILLER_ASN = 2_000_000
MASQUERADE_RULES = """table inet svpn_masq {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 10.77.0.0/24 accept
  }
  chain masq {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/24 oifname "eth0" masquerade
  }
}
"""

_geo_asn = None
_country_ready = False


def _dotted(value):
    return f"{value >> 24}.{value >> 16 & 255}.{value >> 8 & 255}.{value & 255}"


def write_geo():
    global _geo_asn
    if _geo_asn is None:
        peer_row = int(ipaddress.IPv4Address(PEER)) >> HOST_BITS
        _geo_asn = 64512 + peer_row
        mask = (1 << HOST_BITS) - 1
        with CSV.open("w") as out:
            for row in range(ROWS):
                start = row << HOST_BITS
                asn = _geo_asn if row == peer_row else FILLER_ASN + row
                out.write(f'"{_dotted(start)}","{_dotted(start | mask)}",{asn},"synthetic"\n')
    return _geo_asn


def write_country():
    global _country_ready
    if _country_ready:
        return
    target_row = int(ipaddress.IPv4Address(TARGET)) >> HOST_BITS
    mask = (1 << HOST_BITS) - 1
    with COUNTRY_CSV.open("w") as out:
        for row in range(ROWS):
            start = row << HOST_BITS
            country = "RU" if row == target_row else "DE"
            out.write(f'"{_dotted(start)}","{_dotted(start | mask)}",{country}\n')
    _country_ready = True


def enable_target_masquerade():
    # Remote exits need the administrator-provided NAT fixture; unlike the
    # tunnel peer, the external target has no route back to 10.77.0.0/24.
    ssh(
        "mkdir -p /etc/nftables.d && cat > /etc/nftables.d/svpn.nft <<'NFT'\n"
        + MASQUERADE_RULES
        + "NFT\nnft -f /etc/nftables.d/svpn.nft"
    )


def country_args(home=False):
    write_geo()
    write_country()
    args = [
        "svpn",
        "multi",
        "--server",
        f"{SERVER},user=root,identity=/keys/client,countries=RU",
        "--server",
        f"{SERVER2},user=root,identity=/keys/client,countries=DE",
        "--peer-tun-name",
        "svpn0",
        "--tun-name",
        "svpn0",
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        str(CSV),
        "--country-db",
        str(COUNTRY_CSV),
        "--exit-state",
        str(STATE),
        "--stats-interval",
        "1",
    ]
    if home:
        args += ["--home-country", "RU"]
    return args


def sticky_args():
    write_geo()
    return CLIENT_POOL + [
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        str(CSV),
        "--exit-state",
        str(STATE),
        "--stats-interval",
        "1",
    ]


def fresh_state():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.unlink(missing_ok=True)


def opened(path):
    # One-shot flow lines may be dropped by the relay; the heartbeat stats repeat and converge.
    counts = {}
    for host in HOSTS:
        found = re.findall(rf"\[server {re.escape(host)}\][^\n]*opened_flows: (\d+)", path.read_text())
        counts[host] = int(found[-1]) if found else 0
    return counts


def delta(path, baseline):
    counts = opened(path)
    return {host: counts[host] - baseline[host] for host in HOSTS}


def sticky_counters(path):
    found = re.findall(r"sticky: lookup hit (\d+) / miss (\d+) \| failover moves (\d+)", path.read_text())
    assert found, "sticky counters missing from the stats report"
    return tuple(int(value) for value in found[-1])


def sticky_counters_now(path, expected):
    """Non-raising predicate for until(): the periodic sticky report lags the flow
    heartbeat, so poll until the counters converge instead of trusting a snapshot."""
    found = re.findall(r"sticky: lookup hit (\d+) / miss (\d+) \| failover moves (\d+)", path.read_text())
    return bool(found) and tuple(int(value) for value in found[-1]) == expected


def pinned_owner(path, baseline, count):
    """The server that owns every one of `count` new flows, once counters converge."""
    counts = delta(path, baseline)
    return counts if sorted(counts.values()) == [0, count] else None


def kill_and_degrade(process, path, owner):
    """Kill the owner's serve binary, wait for the degraded state; returns the
    pre-kill count of steady 2/2 lines for the later rejoin wait (the rejoin
    may land while post-kill flows are still being verified)."""
    assert process.poll() is None, path.read_text()
    steady = path.read_text().count("serving (2/2 servers ready,")
    degraded = path.read_text().count("serving (1/2 servers ready,")
    command(ssh_to(owner) + ["pkill", "-x", "svpn"])
    until(lambda: path.read_text().count("serving (1/2 servers ready,") > degraded, seconds=15)
    # A checking owner intentionally lends new flows to a reserve without
    # migrating the sticky group. Wait for the actual failed/backoff state
    # before testing failover persistence.
    until(lambda: f"vpn[{owner}]: link failed" in path.read_text(), seconds=15)
    return steady


def wait_rejoined(path, steady):
    until(lambda: path.read_text().count("serving (2/2 servers ready,") > steady, seconds=45)


def test_sticky_dst():
    fresh_state()
    with session("sticky-dst", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        assert f"geo database {CSV}: {ROWS} IPv4 ranges" in path.read_text()
        baseline = opened(path)
        for index in range(10):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 10), seconds=15)
        until(lambda: sticky_counters_now(path, (9, 1, 0)), seconds=15)
        hit, miss, moves = sticky_counters(path)
        assert (hit, miss, moves) == (9, 1, 0), (hit, miss, moves)
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky destination: 10 flows to one dst:port exit via one server (9 hits / 1 miss)")


def test_balance_diff():
    write_geo()
    args = CLIENT_POOL + ["--exit-policy", "balance", "--geo-db", str(CSV)]
    with session("sticky-balance", args=args, server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        assert "geo-db set without exit-policy sticky-asn — ignoring" in path.read_text()
        assert "sticky: lookup" not in path.read_text(), "balance must not group destinations"
        baseline = opened(path)
        for index in range(12):
            tcp_echo(index)
        until(
            lambda: min(delta(path, baseline).values()) >= 4 and sum(delta(path, baseline).values()) == 12,
            seconds=15,
        )
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS balance regression: geo-db ignored, 12 flows still spread by flow key over both servers")


def test_failover_move():
    fresh_state()
    with session("sticky-failover", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(4):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 4), seconds=15)
        counts = delta(path, baseline)
        owner = SERVER if counts[SERVER] else SERVER2
        spare = SERVER2 if owner == SERVER else SERVER
        steady = kill_and_degrade(process, path, owner)
        alive = opened(path)[spare]
        for index in range(4, 10):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - alive == 6 and opened(path)[owner] == 0, seconds=30)
        wait_rejoined(path, steady)
        settled = opened(path)[spare]
        for index in range(10, 16):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - settled == 6 and opened(path)[owner] == 0, seconds=20)
        until(lambda: sticky_counters_now(path, (14, 2, 1)), seconds=15)
        assert sticky_counters(path)[2] == 1, "exactly one failover move expected"
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky failover: killed owner's group moves to the next exit and stays after rejoin")


def test_restart_restore():
    asn = write_geo()
    fresh_state()
    with session("sticky-restart-1", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(4):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 4), seconds=15)
        counts = delta(path, baseline)
        owner = SERVER if counts[SERVER] else SERVER2
        spare = SERVER2 if owner == SERVER else SERVER
        kill_and_degrade(process, path, owner)
        for index in range(4, 8):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - baseline[spare] == 4 and opened(path)[owner] == 0, seconds=30)
    # Clean stop: the client flushes the failover transition to /var/lib/svpn.
    cleanup_verified(process, server_hosts=HOSTS)
    persisted = json.loads(STATE.read_text())
    # Persisted identity is host:port (spec); the default ssh port is 22.
    assert persisted == {"version": 2, "country": {}, "asn": {str(asn): f"{spare}:22"}}, persisted
    with session("sticky-restart-2", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(6):
            tcp_echo(index)
        until(
            lambda: pinned_owner(path, baseline, 6) and pinned_owner(path, baseline, 6)[spare] == 6,
            seconds=15,
        )
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky restart: persisted exit state restores the failed-over owner, no snap-back")


def direct_opened(path):
    found = re.findall(r"direct: opened (\d+) / failed (\d+) / closed (\d+)", path.read_text())
    return tuple(int(value) for value in found[-1]) if found else None


def target_tcp_echo(index, timeout=15):
    payload = bytes([index]) * 65536
    with socket.create_connection((TARGET, 9000), timeout=timeout) as stream:
        stream.settimeout(timeout)
        reader = stream.makefile("rb")
        source = reader.readline().strip().decode()
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        received = reader.read()
    assert ipaddress.ip_address(source)
    assert received == payload, "target TCP echo or half-close failed"
    return source


def udp_echo(peer, payload=b"direct-udp"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(15)
        sock.sendto(payload, (peer, 9000))
        data, _ = sock.recvfrom(65535)
    assert data == payload


def test_country_asn_scope():
    fresh_state()
    enable_target_masquerade()
    try:
        with session("country-asn", args=country_args(), server_hosts=HOSTS, ready_timeout=20) as (
            process,
            path,
        ):
            until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
            command(["ip", "route", "replace", f"{TARGET}/32", "dev", "svpn0"])
            command(["ip", "route", "replace", f"{PEER}/32", "dev", "svpn0"])
            baseline = opened(path)
            source = target_tcp_echo(0)
            assert source == SERVER, source
            tcp_echo(1, peer=PEER)
            until(lambda: delta(path, baseline) == {SERVER: 1, SERVER2: 1}, seconds=20)
        cleanup_verified(process, server_hosts=HOSTS)
    finally:
        ssh("nft delete table inet svpn_masq", check=False)
    print("PASS country+ASN: RU target and DE tunnel peer stay on their scoped servers")


def test_direct_home_and_vpn():
    fresh_state()
    # The internal Compose network intentionally has no default route. Give
    # direct a physical test uplink; ordinary connected routes remain intact.
    command(["ip", "route", "replace", "default", "dev", "eth0"])
    with session("direct-home", args=country_args(home=True), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        command(["ip", "route", "replace", f"{TARGET}/32", "dev", "svpn0"])
        command(["ip", "route", "replace", f"{PEER}/32", "dev", "svpn0"])
        baseline = opened(path)
        source = target_tcp_echo(2)
        assert source == "172.30.77.3", source
        udp_echo(TARGET)
        command(["ping", "-n", "-c", "1", "-W", "2", TARGET])
        tcp_echo(3, peer=PEER)
        until(lambda: direct_opened(path) == (3, 0, 0), seconds=20)
        until(lambda: delta(path, baseline) == {SERVER: 0, SERVER2: 1}, seconds=20)
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS direct+VPN: home TCP/UDP/ICMP bypass servers while DE traffic uses scoped VPN")


TESTS = [
    ("test_sticky_dst", test_sticky_dst),
    ("test_balance_diff", test_balance_diff),
    ("test_failover_move", test_failover_move),
    ("test_restart_restore", test_restart_restore),
    ("test_country_asn_scope", test_country_asn_scope),
    ("test_direct_home_and_vpn", test_direct_home_and_vpn),
]
