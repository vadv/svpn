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

test_zombie_silent_storm_reclaims_flow_slots floods the blackholed
port without any reply: the handshakes never complete, so the flows
stay unproven — the incident's zombie shape. The 30 s TTL must fire
under the flood, and once the storm stops the flow tables on both
peers must drain back to their working set instead of hoarding the
zombie slots (the pre-fix incident hoarded them for hours).
Established-but-silent connections are proven (a completed handshake
is proof of life) and live by the idle rules — not zombies.

shortcut: the flood daemon behind the incident is not reproduced here
(test storms instead), replace with the real generator if it is ever
identified.
"""

from __future__ import annotations

import re
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
BUDGET_WINDOW = 45  # seconds until the first TTL expiry is due
DRAIN_WINDOW = 75  # seconds for the flow tables to empty after the storm
FLOW_TABLE_BASELINE = 32  # working set (probes + veteran) after a drain
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


def active_flows(path):
    """Flow-table size of each peer from the latest heartbeat stats."""

    def latest(prefixed):
        for line in reversed(path.read_text().splitlines()):
            if ("[server]" in line) == prefixed and (hit := re.search(r"active_flows: (\d+)", line)):
                return int(hit.group(1))
        return None

    return latest(False), latest(True)


def await_drain(path, veteran):
    """Wait for both peers' flow tables to return to the working set.

        Kernel SYN retransmits re-open flows after each TTL close, so the
        honest slot-reclaim metric is the steady-state table size, not a
    close count: after the storm sockets are gone every re-opened zombie
    expires within one more TTL.
    """
    deadline = time.monotonic() + DRAIN_WINDOW
    warm = time.monotonic()
    while True:
        client, server = active_flows(path)
        if (
            client is not None
            and server is not None
            and client <= FLOW_TABLE_BASELINE
            and server <= FLOW_TABLE_BASELINE
        ):
            return
        assert time.monotonic() < deadline, (
            f"flow tables did not drain within the budget: client={client} server={server}"
        )
        if time.monotonic() - warm >= 3:
            push_echo(veteran, 0x5B)
            warm = time.monotonic()


def close_all(sockets):
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def client_lines(path, marker, peers="client"):
    """Count journal lines with `marker`. "client" excludes the [server]
    copy (its ids differ and must not inflate client assertions); "any"
    counts both peers."""
    return sum(
        1
        for line in path.read_text().splitlines()
        if marker in line and (peers == "any" or "[server]" not in line)
    )


def await_closes(path, need, seconds, veteran, marker="flow_close", peers="client"):
    """Wait for `need` client-side `marker` lines, keeping the veteran warm.

    The echo service kills connections idle for 20 s, so the veteran gets
    a byte exchange every few seconds while the budget window runs.
    """
    deadline = time.monotonic() + seconds
    warm = time.monotonic()
    while client_lines(path, marker, peers) < need:
        assert time.monotonic() < deadline, f"{marker} lines did not reach {need} within the budget"
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
        assert client_lines(path, "flow limit reached") == 0, (
            "new handshakes were refused under the zombie storm"
        )
        assert process.poll() is None, "the client died during the zombie storm"
        close_all(sockets)
        veteran.close()
        print("PASS zombie storm keeps established and new flows moving")


def test_zombie_silent_storm_reclaims_flow_slots():
    ensure_fds()
    with session("zombie-reclaim") as (process, path):
        veteran = socket.create_connection((PEER, 9000), timeout=15)
        push_echo(veteran, 0x5A)  # proven: must outlive the budget sweep
        before = client_lines(path, "lifetime expired", peers="any")
        # A true zombie never gets a SYN-ACK: the target blackholes the port.
        ssh(f"iptables -A INPUT -p tcp --dport {BLACKHOLE_PORT} -j DROP")
        try:
            sockets = storm(path, (PEER, BLACKHOLE_PORT), SILENT)
            # The TTL must fire under the flood, not only after it ends.
            # Either peer proves it: on slow runners the server sweep wins
            # the race and the client reclaims via the close notification.
            await_closes(
                path,
                before + 1,
                BUDGET_WINDOW,
                veteran,
                "lifetime expired",
                peers="any",
            )
        finally:
            ssh(f"iptables -D INPUT -p tcp --dport {BLACKHOLE_PORT} -j DROP", check=False)
        close_all(sockets)  # stop the kernel SYN retransmit churn at the source
        await_drain(path, veteran)
        push_echo(veteran, 0x5B)
        assert client_lines(path, "flow limit reached") == 0, (
            "new handshakes were refused under the zombie storm"
        )
        assert process.poll() is None, "the client died during the zombie storm"
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
            return client_lines(path, "flow_close")

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
