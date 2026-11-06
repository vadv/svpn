"""Zombie half-open flood (EPIC-023): the 2026-11-06 FLOW_CAP incident.

A TCP flow slot is allocated on the first TUN SYN while the local kernel
handshake hangs (the far side blackholes), and an unproven half-open TCP
flow is reclaimed only by the proven TTL (30 s).  A flood of stuck
handshakes therefore pins the flow table: that is what a runaway local
daemon did on 2026-11-06 (4160 flows, every new handshake refused,
"hang on all servers").

test_zombie_storm_keeps_flows_moving floods one blackholed port with
4096 stuck handshakes (the FLOW_CAP fill), then proves an established
flow survives byte-exact and a brand new handshake still passes
(displacement admission evicts unproven zombies), with zero refusals.

test_zombie_silent_storm_reclaims_flow_slots floods the echo port
without sending data: the far side accepts but never speaks back, so
the flows stay unproven — the incident's zombie shape — and must be
reclaimed by the 30 s TTL while proven flows keep working.

shortcut: the flood daemon behind the incident is not reproduced here
(test storms instead), replace with the real generator if it is ever
identified.
"""

from __future__ import annotations

import resource
import socket
import time

from _lib import (
    PEER,
    recv_exact,
    session,
    ssh,
    until,
)

STORM = 4096  # FLOW_CAP in src/session.rs — displacement must engage at the cap
SILENT = 512  # keeps the echo service's thread-per-connection load sane
BUDGET_WINDOW = 45  # FLOW_BUDGET 30 s + the 2 s expire tick + slack
FAIL_FAST = 15  # a refused dial must error well before the 30 s flow TTL
BLACKHOLE_PORT = 7003


def ensure_fds():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = STORM + 1024
    assert hard >= need, f"RLIMIT_NOFILE hard {hard} cannot hold {STORM} storm sockets"
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(soft, need)), hard))


def push_echo(stream, byte=0x5A):
    # the echo service returns the data as-is; b"EOF" comes only after SHUT_WR
    payload = bytes([byte]) * 4096
    stream.sendall(payload)
    received = recv_exact(stream, len(payload), 20)
    assert received == payload, "echo payload mismatch"


def storm(path, target, count):
    """Fire `count` non-blocking connects and prove they reached the table.

    The kernel handshakes stay half-open when the target blackholes; the
    flow slots are still allocated on the first SYN — that is the flood.
    """
    before = path.read_text().count("flow_request")
    sockets = []
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(target)
        sockets.append(sock)
    until(
        lambda: path.read_text().count("flow_request") >= before + count,
        seconds=30,
    )
    assert path.read_text().count("flow_request") >= before + count, (
        f"only {path.read_text().count('flow_request') - before}/{count} flood SYNs reached the flow table"
    )
    return sockets


def close_all(sockets):
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def await_closes(path, need, seconds, veteran):
    """Wait for `need` flow_close lines, keeping the veteran warm.

    The echo service kills connections idle for 20 s, so the veteran gets
    a byte exchange every few seconds while the budget window runs.
    """
    deadline = time.monotonic() + seconds
    warm = time.monotonic()
    while path.read_text().count("flow_close") < need:
        assert time.monotonic() < deadline, "flow slots were not reclaimed within the budget"
        if time.monotonic() - warm >= 3:
            push_echo(veteran, 0x5B)
            warm = time.monotonic()


def test_zombie_storm_keeps_flows_moving():
    ensure_fds()
    with session("zombie-storm") as (process, path):
        veteran = socket.create_connection((PEER, 9000), timeout=15)
        push_echo(veteran, 0x5A)  # established and proven before the storm
        ssh(f"iptables -A INPUT -p tcp --dport {BLACKHOLE_PORT} -j DROP")
        sockets = storm(path, (PEER, BLACKHOLE_PORT), STORM)
        try:
            push_echo(veteran, 0x5B)  # established flows survive the full table
            fresh = socket.create_connection((PEER, 9000), timeout=15)
            sockets.append(fresh)  # a new handshake passes: displacement admission
            push_echo(fresh, 0x5C)
        finally:
            ssh(f"iptables -D INPUT -p tcp --dport {BLACKHOLE_PORT} -j DROP", check=False)
        journal = path.read_text()
        assert "flow limit reached" not in journal, "new handshakes were refused under the zombie storm"
        assert process.poll() is None, "the client died during the zombie storm"
        close_all(sockets)
        veteran.close()
        print("PASS zombie storm keeps established and new flows moving")


def test_zombie_silent_storm_reclaims_flow_slots():
    ensure_fds()
    with session("zombie-reclaim") as (process, path):
        veteran = socket.create_connection((PEER, 9000), timeout=15)
        push_echo(veteran, 0x5A)  # proven: must outlive the budget sweep
        before = path.read_text().count("flow_close")
        sockets = storm(path, (PEER, 9000), SILENT)

        def closes():
            return path.read_text().count("flow_close")

        await_closes(path, before + SILENT, BUDGET_WINDOW, veteran)
        assert closes() >= before + SILENT, "zombie flows outlived the flow budget"
        push_echo(veteran, 0x5B)
        journal = path.read_text()
        assert "flow limit reached" not in journal, "new handshakes were refused under the zombie storm"
        assert process.poll() is None, "the client died during the zombie storm"
        close_all(sockets)
        veteran.close()
        print("PASS silent zombie flows reclaim slots within the budget")


def test_failed_handshake_fails_fast():
    with session("zombie-fail-fast") as (process, path):
        veteran = socket.create_connection((PEER, 9000), timeout=15)
        push_echo(veteran, 0x5A)
        before = path.read_text().count("flow_close")
        start = time.monotonic()
        refused = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        refused.settimeout(FAIL_FAST)
        try:
            refused.connect((PEER, BLACKHOLE_PORT + 1))  # nothing listens here
            raise AssertionError("a dial to a dead port connected")
        except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
            pass
        except TimeoutError as exc:
            raise AssertionError(f"a refused handshake hung {FAIL_FAST}s instead of failing fast") from exc
        finally:
            refused.close()
        assert time.monotonic() - start < FAIL_FAST, "a refused handshake did not fail fast"

        def closes():
            return path.read_text().count("flow_close")

        # a target RST must not close flows early (it may be out of window),
        # so the slot is reclaimed by the flow TTL — allow the budget window
        await_closes(path, before + 1, BUDGET_WINDOW, veteran)
        assert closes() >= before + 1, "a refused handshake kept its slot past the flow budget"
        push_echo(veteran, 0x5B)
        assert process.poll() is None, "the client died on a refused handshake"
        veteran.close()
        print("PASS a refused handshake fails fast and frees its slot")


TESTS = [
    (test_zombie_storm_keeps_flows_moving.__name__, test_zombie_storm_keeps_flows_moving),
    (test_zombie_silent_storm_reclaims_flow_slots.__name__, test_zombie_silent_storm_reclaims_flow_slots),
    (test_failed_handshake_fails_fast.__name__, test_failed_handshake_fails_fast),
]
