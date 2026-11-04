"""Sticky group: explicit sticky pins by DNS name with episodic re-resolve."""

import contextlib
import ipaddress
import json
import pathlib
import re
import socket

from _lib import SERVER, SERVER2, cleanup_verified, command, session, ssh_to, until
from suite_sticky_asn import enable_target_masquerade

HOSTS = (SERVER, SERVER2)
DNS = "172.30.77.7"
RECORDS = pathlib.Path("/dns/records")
CONFIG = pathlib.Path("/tmp/e2e-sticky.hcl")
STATE = pathlib.Path("/var/lib/svpn/exit-state.json")
RESOLV = pathlib.Path("/etc/resolv.conf")
TARGET_A = "172.30.77.4"  # target
TARGET_B = "172.30.77.6"  # target_by


@contextlib.contextmanager
def dns_resolv():
    """Point the client resolver at the file-backed DNS, then restore."""
    original = RESOLV.read_text()
    RESOLV.write_text(f"nameserver {DNS}\n")
    try:
        yield
    finally:
        RESOLV.write_text(original)


def set_records(*lines):
    RECORDS.write_text("\n".join(lines) + "\n")


def sticky_config(*sticky_blocks, with_state=True):
    state = f'  state = "{STATE}"\n' if with_state else ""
    CONFIG.write_text(
        'ssh {\n  user = "root"\n  identity = "/keys/client"\n}\n'
        'log_level = "debug"\n'
        'tunnel {\n  peer_name = "svpn0"\n  name = "svpn0"\n}\n'
        'transport {\n  stats = "1s"\n}\n'
        + f"fallback_sticky {{\n{state}}}\n"
        + f'server "s1" {{\n  address = "{SERVER}"\n}}\n'
        + f'server "s2" {{\n  address = "{SERVER2}"\n}}\n'
        + "".join(sticky_blocks)
    )
    return ["svpn", "multi", "--config", str(CONFIG)]


def name_block(via, every="5s"):
    return f'sticky "pin" {{\n  names = ["pin.example"]\n  via = {via}\n  every = "{every}"\n}}\n'


def fresh_state():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.unlink(missing_ok=True)


def target_tcp_echo(index, destination, timeout=15):
    payload = bytes([index]) * 65536
    with socket.create_connection((destination, 9000), timeout=timeout) as stream:
        stream.settimeout(timeout)
        reader = stream.makefile("rb")
        source = reader.readline().strip().decode()
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        received = reader.read()
    assert ipaddress.ip_address(source)
    assert received == payload, "target TCP echo or half-close failed"
    return source


def opened(path):
    counts = {}
    for host in HOSTS:
        found = re.findall(rf"\[server {re.escape(host)}\][^\n]*opened_flows: (\d+)", path.read_text())
        counts[host] = int(found[-1]) if found else 0
    return counts


def purged(path):
    found = re.findall(
        r"sticky: blocks matched \d+ \| resolve ok \d+ / fail \d+ \| ips \d+ \(purged (\d+)\)",
        path.read_text(),
    )
    return int(found[-1]) if found else None


def route_targets_into_tun(*targets):
    """Local-subnet destinations must enter the TUN to be routed by svpn."""
    for target in targets:
        command(["ip", "route", "replace", f"{target}/32", "dev", "svpn0"])


def kill_server(owner, path):
    command(ssh_to(owner) + ["pkill", "-x", "svpn"])
    until(lambda: f"vpn[{owner}]: link failed" in path.read_text(), seconds=15)


def test_name_pin():
    """The resolver fills the name set once; every flow pins to the owner."""
    fresh_state()
    enable_target_masquerade()
    set_records(f"pin.example {TARGET_A}")
    try:
        with dns_resolv():
            with session(
                "sticky-name-pin",
                args=sticky_config(name_block('["s1"]')),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                route_targets_into_tun(TARGET_A)
                sources = {target_tcp_echo(index, "pin.example") for index in range(6)}
                assert sources == {SERVER}, sources
                assert opened(path)[SERVER2] == 0
            cleanup_verified(process, server_hosts=HOSTS)
    finally:
        command(
            ["ssh", "-i", "/keys/client", f"root@{SERVER}", "nft delete table inet svpn_masq"], check=False
        )
    print("PASS sticky name: pin.example exits via the pinned server only")


def test_first_match_over_later_blocks():
    """The name block sits before an overlapping ips block and wins."""
    fresh_state()
    enable_target_masquerade()
    set_records(f"pin.example {TARGET_A}")
    overlap = 'sticky "by-ip" {\n  ips = ["172.30.77.4/32"]\n  via = ["s2"]\n}\n'
    try:
        with dns_resolv():
            with session(
                "sticky-first-match",
                args=sticky_config(name_block('["s1"]'), overlap),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                route_targets_into_tun(TARGET_A)
                sources = {target_tcp_echo(index, "pin.example") for index in range(4)}
                assert sources == {SERVER}, sources
                # Even a direct connection to the resolved IP hits the first block.
                direct = {target_tcp_echo(index, TARGET_A) for index in range(4, 8)}
                assert direct == {SERVER}, direct
            cleanup_verified(process, server_hosts=HOSTS)
    finally:
        command(
            ["ssh", "-i", "/keys/client", f"root@{SERVER}", "nft delete table inet svpn_masq"], check=False
        )
    print("PASS sticky first-match: the first block wins for names and its IPs")


def test_failover_without_snapback():
    fresh_state()
    enable_target_masquerade()
    set_records(f"pin.example {TARGET_A}")
    try:
        with dns_resolv():
            with session(
                "sticky-name-failover",
                args=sticky_config(name_block('["s1", "s2"]')),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                route_targets_into_tun(TARGET_A)
                owner = {target_tcp_echo(i, "pin.example") for i in range(4)}.pop()
                spare = SERVER2 if owner == SERVER else SERVER
                kill_server(owner, path)
                assert {target_tcp_echo(i, "pin.example") for i in range(4, 8)} == {spare}
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=45)
                assert {target_tcp_echo(i, "pin.example") for i in range(8, 12)} == {spare}
            cleanup_verified(process, server_hosts=HOSTS)
    finally:
        command(
            ["ssh", "-i", "/keys/client", f"root@{SERVER}", "nft delete table inet svpn_masq"], check=False
        )
    print("PASS sticky name failover: the group moves to the reserve and stays")


def test_ip_change_purges_stale_pins():
    fresh_state()
    for host in HOSTS:
        enable_target_masquerade(host)
    set_records(f"pin.example {TARGET_A}")
    try:
        with dns_resolv():
            with session(
                "sticky-name-purge",
                args=sticky_config(name_block('["s1"]')),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                route_targets_into_tun(TARGET_A, TARGET_B)
                assert {target_tcp_echo(i, "pin.example") for i in range(4)} == {SERVER}
                # Re-point the name: two 5s refreshes wash the old IP out.
                set_records(f"pin.example {TARGET_B}")
                until(lambda: purged(path) is not None and purged(path) >= 1, seconds=30)
                assert {target_tcp_echo(i, "pin.example") for i in range(4, 8)} == {SERVER}
            cleanup_verified(process, server_hosts=HOSTS)
    finally:
        for host in HOSTS:
            command(ssh_to(host) + ["nft delete table inet svpn_masq"], check=False)
    print("PASS sticky purge: a re-resolved name moves its pins, stale IPs wash out")


def test_restart_restores_pinned_owner():
    fresh_state()
    enable_target_masquerade()
    set_records(f"pin.example {TARGET_A}")
    try:
        with dns_resolv():
            with session(
                "sticky-name-restart-1",
                args=sticky_config(name_block('["s1", "s2"]')),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                route_targets_into_tun(TARGET_A)
                owner = {target_tcp_echo(i, "pin.example") for i in range(4)}.pop()
                spare = SERVER2 if owner == SERVER else SERVER
                kill_server(owner, path)
                assert {target_tcp_echo(i, "pin.example") for i in range(4, 8)} == {spare}
            cleanup_verified(process, server_hosts=HOSTS)
            persisted = json.loads(STATE.read_text())
            assert persisted == {
                "version": 1,
                "asn": {},
                "sticky": {"name:pin.example": f"{spare}:22"},
            }, persisted
            with session(
                "sticky-name-restart-2",
                args=sticky_config(name_block('["s1", "s2"]')),
                server_hosts=HOSTS,
                ready_timeout=20,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=45)
                route_targets_into_tun(TARGET_A)
                assert {target_tcp_echo(i, "pin.example") for i in range(8, 14)} == {spare}
            cleanup_verified(process, server_hosts=HOSTS)
    finally:
        command(
            ["ssh", "-i", "/keys/client", f"root@{SERVER}", "nft delete table inet svpn_masq"], check=False
        )
    print("PASS sticky restart: the persisted name pin restores, no snap-back")


TESTS = [
    ("test_name_pin", test_name_pin),
    ("test_first_match_over_later_blocks", test_first_match_over_later_blocks),
    ("test_failover_without_snapback", test_failover_without_snapback),
    ("test_ip_change_purges_stale_pins", test_ip_change_purges_stale_pins),
    ("test_restart_restores_pinned_owner", test_restart_restores_pinned_owner),
]
