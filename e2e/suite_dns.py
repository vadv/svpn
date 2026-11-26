"""DNS group: UDP/53 from the client TUN is resolved by the exit that carries the traffic.

The two exit containers resolve through the file-backed DNS fixture, which
answers per asker and journals every query: who resolved a name is on record.
"""

import contextlib
import pathlib
import socket
import struct
import time

from _lib import LOCAL, SERVER, SERVER2, cleanup_verified, command, session, until
from suite_sticky_asn import enable_target_masquerade

HOSTS = (SERVER, SERVER2)
DNS = "172.30.77.7"
RECORDS = pathlib.Path("/dns/records")
QUERIES = pathlib.Path("/dns/queries")
CONFIG = pathlib.Path("/tmp/e2e-dns.hcl")
# The fixture's TTL, and what a stale answer may promise.
TTL = 5
STALE_TTL = 30
T_A = 1


def set_records(*lines):
    RECORDS.write_text("\n".join(lines) + "\n")


def asked(name):
    """Which exit's resolver was asked for `name`, in order."""
    return [line.split()[0] for line in QUERIES.read_text().splitlines() if line.split()[1] == name]


def dns_config(mode):
    dns = 'dns {\n  mode = "exit"\n}\n' if mode else ""
    CONFIG.write_text(
        'ssh {\n  user = "root"\n  identity = "/keys/client"\n}\n'
        'log_level = "debug"\n'
        'tunnel {\n  peer_name = "svpn0"\n  name = "svpn0"\n}\n'
        'transport {\n  stats = "1s"\n}\n'
        + dns
        + f'server "s1" {{\n  address = "{SERVER}"\n}}\n'
        + f'server "s2" {{\n  address = "{SERVER2}"\n}}\n'
        + 'sticky "cdn" {\n  ips = ["203.0.113.0/24"]\n  via = ["s2"]\n}\n'
    )
    return ["svpn", "multi", "--config", str(CONFIG)]


@contextlib.contextmanager
def resolver_routed_into_tun():
    """The operator sends the resolver's address through the tunnel."""
    command(["ip", "route", "replace", f"{DNS}/32", "dev", "svpn0", "src", LOCAL])
    try:
        yield
    finally:
        command(["ip", "route", "del", f"{DNS}/32"], check=False)


def query(name, timeout=8):
    """One A query from the tunnel's address, as a stub sends it: (seconds, addresses, ttl, rcode)."""
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", T_A, 1)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((LOCAL, 0))
        sock.settimeout(timeout)
        sock.sendto(packet, (DNS, 53))
        data, peer = sock.recvfrom(4096)
    assert peer == (DNS, 53), f"the reply must come from the resolver the stub asked: {peer}"
    ident, flags, _questions, answers, _authority, _additional = struct.unpack_from("!HHHHHH", data, 0)
    assert ident == 0x4242 and flags & 0x8000, "a response to this query"
    offset = 12 + len(qname) + 4
    addresses, ttls = [], []
    for _ in range(answers):
        assert data[offset : offset + 2] == b"\xc0\x0c", "the record owner is the question"
        rtype, _class, ttl, length = struct.unpack_from("!HHIH", data, offset + 2)
        assert rtype == T_A and length == 4, "an A record"
        addresses.append(socket.inet_ntoa(data[offset + 12 : offset + 16]))
        ttls.append(ttl)
        offset += 12 + length
    return time.monotonic() - started, addresses, min(ttls, default=0), flags & 0xF


def test_name_is_resolved_where_its_traffic_leaves():
    """An address that leaves through s2 is resolved by s2, then served from the cache."""
    QUERIES.write_text("")
    set_records(
        f"cdn.example 203.0.113.10@{SERVER}",  # what s1's location would answer
        f"cdn.example 203.0.113.99@{SERVER2}",  # what s2's location answers
    )
    with session("dns-exit", args=dns_config(mode=True), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        with resolver_routed_into_tun():
            _spent, addresses, ttl, rcode = query("cdn.example")
            assert (addresses, rcode) == (["203.0.113.99"], 0), "the exit's own answer"
            assert ttl == TTL, "the TTL as received"
            # Probed through whichever exit is default, then asked again where
            # the address goes; the last ask is always the exit that carries it.
            assert asked("cdn.example") in ([SERVER2], [SERVER, SERVER2]), asked("cdn.example")
            _spent, again, ttl_again, _rcode = query("cdn.example")
            assert again == addresses, "the cache answers inside the TTL"
            assert ttl_again <= TTL, "never more TTL than the answer carried"
            assert len(asked("cdn.example")) <= 2, "a cached answer asks nobody"
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS dns exit: a name resolves at the exit its traffic takes, then from the cache")


def test_ttl_is_honoured_and_failures_serve_the_cache():
    """The TTL ends the cache; a dead resolver gets the stale answer, or SERVFAIL."""
    QUERIES.write_text("")
    set_records("plain.example 198.51.100.7", "never.example -")
    with session("dns-cache", args=dns_config(mode=True), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        with resolver_routed_into_tun():
            _spent, addresses, _ttl, _rcode = query("plain.example")
            assert addresses == ["198.51.100.7"]
            resolved = len(asked("plain.example"))
            assert resolved >= 1
            _spent, cached, _ttl, _rcode = query("plain.example")
            assert cached == addresses and len(asked("plain.example")) == resolved
            # Past the TTL the exit is asked again, not the cache.
            time.sleep(TTL + 0.5)
            _spent, fresh, _ttl, _rcode = query("plain.example")
            assert fresh == addresses and len(asked("plain.example")) > resolved

            # The resolver goes silent: the answer past its TTL stands in,
            # after the exit's own wait, and holds for a while.
            set_records("plain.example -", "never.example -")
            time.sleep(TTL + 0.5)
            spent, stale, ttl, rcode = query("plain.example")
            assert (stale, rcode) == (addresses, 0), "the kept answer instead of an error"
            assert 0 < ttl <= STALE_TTL, "a stale answer promises little"
            assert spent >= 2.0, "the exit was asked first and waited for"
            failures = len(asked("plain.example"))
            spent, held, _ttl, _rcode = query("plain.example")
            assert (held, rcode) == (addresses, 0)
            assert spent < 1.0 and len(asked("plain.example")) == failures, "not asked again at once"

            # Nothing kept: the stub is told so.
            _spent, none, _ttl, rcode = query("never.example")
            assert (none, rcode) == ([], 2), "SERVFAIL"
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS dns cache: TTL honoured, stale on failure, SERVFAIL with nothing kept")


def test_without_the_mode_udp_53_is_ordinary_traffic():
    """No `dns` block: the query travels to the resolver as any other UDP flow."""
    QUERIES.write_text("")
    set_records("plain.example 198.51.100.7")
    try:
        for host in HOSTS:
            enable_target_masquerade(host)
        with session("dns-off", args=dns_config(mode=False), server_hosts=HOSTS, ready_timeout=20) as (
            process,
            path,
        ):
            until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
            with resolver_routed_into_tun():
                _spent, addresses, ttl, _rcode = query("plain.example")
            assert addresses == ["198.51.100.7"]
            assert ttl == TTL, "straight from the resolver, no cache in between"
            assert asked("plain.example") == [SERVER] or asked("plain.example") == [SERVER2]
            assert "dns: " not in path.read_text(), "the hub keeps out of DNS"
        cleanup_verified(process, server_hosts=HOSTS)
    finally:
        for host in HOSTS:
            command(
                [
                    "ssh",
                    "-i",
                    "/keys/client",
                    f"root@{host}",
                    "nft delete table inet svpn_masq",
                ],
                check=False,
            )
    print("PASS dns off: without the block UDP/53 is ordinary traffic")


TESTS = [
    ("test_name_is_resolved_where_its_traffic_leaves", test_name_is_resolved_where_its_traffic_leaves),
    ("test_ttl_is_honoured_and_failures_serve_the_cache", test_ttl_is_honoured_and_failures_serve_the_cache),
    ("test_without_the_mode_udp_53_is_ordinary_traffic", test_without_the_mode_udp_53_is_ordinary_traffic),
]
