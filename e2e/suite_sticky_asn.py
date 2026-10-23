"""Sticky-asn group: destination pinning, balance regression, failover and restart restore."""

import ipaddress
import json
import pathlib
import re

from _lib import (
    CLIENT_POOL,
    PEER,
    SERVER,
    SERVER2,
    cleanup_verified,
    command,
    session,
    ssh_to,
    tcp_echo,
    until,
)

HOSTS = (SERVER, SERVER2)
CSV = pathlib.Path("/tmp/e2e-asn.csv")
STATE = pathlib.Path("/var/lib/svpn/exit-state.json")
# One /17 block per row: 131072 synthetic rows pass Geo::load's 100k-row floor and give
# every subnet a distinct ASN, so rendezvous picks differ across destination groups.
HOST_BITS = 15
ROWS = 1 << (32 - HOST_BITS)
FILLER_ASN = 2_000_000

_geo_asn = None


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
    assert persisted == {"version": 1, "owners": {str(asn): f"{spare}:22"}}, persisted
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


TESTS = [
    ("test_sticky_dst", test_sticky_dst),
    ("test_balance_diff", test_balance_diff),
    ("test_failover_move", test_failover_move),
    ("test_restart_restore", test_restart_restore),
]
