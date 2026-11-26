"""Re-selection: ban expiry, a degraded or drifting incumbent, symmetric noise; flows survive."""

import os
import re
import socket
import time

from _lib import (
    CLIENT,
    PEER,
    cleanup_verified,
    recv_exact,
    server_iface,
    session,
    ssh,
    tcp_echo,
    until,
)

# SVPN_TEST_BAN_BACKOFF_SECS (selector.rs ban_backoff_start) shrinks the first
# ban so the expiry-driven challenge fits the test budget. The remeasure
# cadence gates every challenge; 1 s opens it right away.
ENV = dict(os.environ, SVPN_TEST_BAN_BACKOFF_SECS="3")
ARGS = CLIENT + ["--remeasure-interval", "1"]
UDP_TRANSPORTS = "mosh|quic|webrtc|obfs"
# A data flow over a UDP transport, as the server reports opening it.
FLOW_OVER_UDP = (
    r"flow_open role=server id=\d+(?: generation=\d+)?(?: channel=\d+)? "
    r"transport=(" + UDP_TRANSPORTS + r")"
)
# Every port a strategy may hold on the server (transport.udp_ports, 60000–60009).
STRATEGY_PORTS = range(60000, 60010)


def tcp_flow_ids(log):
    return set(
        re.findall(
            r"flow_open role=server id=(\d+)(?: generation=\d+)?(?: channel=\d+)? transport=tcp",
            log,
        )
    )


def flow_over(candidate, log):
    return re.search(
        r"flow_open role=server id=\d+(?: generation=\d+)?(?: channel=\d+)? transport=" + candidate,
        log,
    )


def incumbent(path):
    """The transport the first flow rides, and the server port its replies leave from."""
    log = path.read_text()
    adopted = re.search(r"transport=(" + UDP_TRANSPORTS + ")", log).group(1)
    strategies, ports = re.search(r"serve: strategies=([\w+]+) udp_ports=([\d,]+)", log).groups()
    return adopted, dict(zip(strategies.split("+"), ports.split(",")))[adopted]


def delay_replies(ports, delay):
    """Slow the server's replies from `ports` by `delay` (netem terms). Only the
    replies are touched: p90 degrades without loss, so live flows survive."""
    dev = server_iface()
    ssh(
        f"tc qdisc add dev {dev} root handle 1: prio"
        f" && tc qdisc add dev {dev} parent 1:3 handle 30: netem delay {delay}"
    )
    for port in ports:
        ssh(
            f"tc filter add dev {dev} protocol ip parent 1:0 prio 3"
            f" u32 match ip sport {port} 0xffff flowid 1:3"
        )


def undelay_replies():
    # The root qdisc goes wholesale: repeated `change` on a prio+netem
    # stack is brittle across iproute2 versions.
    ssh(f"tc qdisc del dev {server_iface()} root", check=False)


def wait_until_slow(path, candidate, floor_ms, seconds=30):
    """The emulated delay has to show in `candidate`'s probes before a wait
    for a verdict means anything. Otherwise the case fails at once, with the
    server's qdisc, instead of timing out on a verdict that was never due."""

    def slowest():
        found = re.findall(rf"probe: {candidate} p90=(\d+)ms", path.read_text())
        return max((int(ms) for ms in found), default=0)

    try:
        until(lambda: slowest() >= floor_ms, seconds=seconds)
    except AssertionError as error:
        dev = server_iface()
        state = ssh(f"tc -s qdisc show dev {dev}; tc -s filter show dev {dev}").stdout
        raise AssertionError(
            f"the emulated delay never reached {candidate} (server {dev}):\n{state}"
        ) from error


def test_udp_reselect_after_ban_expiry():
    # Unblocked UDP serves new flows without interrupting the TCP veteran.
    ssh("iptables -w -A INPUT -p udp -j DROP")
    try:
        with session("reselect", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
            # Keep the echo target's 20 s read timeout alive during the switch.
            with socket.create_connection((PEER, 9000), timeout=5) as veteran:
                veteran.sendall(b"before")
                assert recv_exact(veteran, 6) == b"before"
                until(lambda: tcp_flow_ids(path.read_text()), seconds=5)
                veterans = tcp_flow_ids(path.read_text())
                assert veterans, "the established flow is not over TCP"

                ssh("iptables -w -D INPUT -p udp -j DROP")
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    veteran.sendall(b"keep")
                    assert recv_exact(veteran, 4) == b"keep"
                    log = path.read_text()
                    if re.search(r"reselection: \w+ replaces", log):
                        break
                    time.sleep(2)
                else:
                    raise AssertionError("no reselection after UDP was unblocked:\n" + log[-2000:])

                # New flows leave TCP: a fresh transfer rides a UDP channel.
                tcp_echo(31)
                until(
                    lambda: re.search(
                        r"flow_open role=server id=\d+(?: generation=\d+)?(?: channel=\d+)? "
                        r"transport=(?:mosh|quic|webrtc|obfs)",
                        path.read_text(),
                    ),
                    seconds=10,
                )
                log = path.read_text()
                assert "challenge: probing" in log, log[-2000:]
                assert tcp_flow_ids(log) == veterans, "a new flow opened over TCP after adoption"
                # The pre-switch TCP flow still carries data.
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in log, log[-2000:]
            assert process.poll() is None
        cleanup_verified(process)
    finally:
        ssh("iptables -w -D INPUT -p udp -j DROP", check=False)
    print("PASS udp_reselect_after_ban_expiry: new flows move to UDP, the TCP veteran survives")


def test_degraded_incumbent_switches_and_drains():
    # The UDP incumbent degrades -> a challenger separates from it by the
    # smoothed margin -> reselection; the flow opened before the switch keeps
    # flowing on the draining channel.
    with session("degrade", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=20) as veteran:
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(lambda: re.search(FLOW_OVER_UDP, path.read_text()), seconds=30)
            adopted, port = incumbent(path)
            # Only the incumbent's replies are delayed, so nothing is lost.
            delay_replies([port], "150ms")
            try:
                wait_until_slow(path, adopted, 140)
                switched = None
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    veteran.sendall(b"keep")
                    assert recv_exact(veteran, 4) == b"keep"
                    switched = re.search(r"reselection: (\w+) replaces", path.read_text())
                    if switched:
                        break
                    time.sleep(2)
                else:
                    raise AssertionError(
                        f"no reselection away from degraded {adopted}:\n" + path.read_text()[-2000:]
                    )
                winner = switched.group(1)
                assert winner != adopted, "switched onto the same degraded transport"
                # New flows ride the new transport; the veteran still flows.
                tcp_echo(32)
                until(lambda: flow_over(winner, path.read_text()), seconds=15)
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in path.read_text()
            finally:
                undelay_replies()
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS degraded_incumbent_switches_and_drains: margin winner takes over, the veteran drains")


def test_incumbent_drift_ramp_switches():
    # A slow ramp on the incumbent must still end in a reselection once
    # the smoothed estimates separate — without breaking live traffic.
    with session("drift", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=20) as veteran:
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(lambda: re.search(FLOW_OVER_UDP, path.read_text()), seconds=30)
            adopted, port = incumbent(path)
            try:
                # Three small steps beat one spike: each level must sit
                # in the EWMA window before the next lands.
                for step in (40, 90, 150):
                    undelay_replies()
                    delay_replies([port], f"{step}ms")
                    wait_until_slow(path, adopted, step - 5)
                    switched = None
                    deadline = time.monotonic() + 60
                    while time.monotonic() < deadline:
                        veteran.sendall(b"keep")
                        assert recv_exact(veteran, 4) == b"keep"
                        switched = re.search(r"reselection: (\w+) replaces", path.read_text())
                        if switched:
                            break
                        time.sleep(2)
                    if switched:
                        break
                else:
                    raise AssertionError(
                        f"the drift ramp never moved traffic off {adopted}:\n" + path.read_text()[-2000:]
                    )
                winner = switched.group(1)
                assert winner != adopted, "switched onto the same drifting transport"
                tcp_echo(33)
                until(lambda: flow_over(winner, path.read_text()), seconds=15)
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in path.read_text()
            finally:
                undelay_replies()
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS incumbent_drift_ramp_switches: ramped delay ends in reselection")


def test_symmetric_noise_does_not_switch():
    # Identical delay with jitter on every strategy port puts all
    # candidates inside one noise band: no reselection may land, and the
    # flow opened before the noise keeps flowing on its transport.
    with session("noise", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        # A flow has to be opened for one to show up in the log: the probes
        # alone are not `flow_open`.
        with socket.create_connection((PEER, 9000), timeout=20) as veteran:
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(lambda: re.search(FLOW_OVER_UDP, path.read_text()), seconds=30)
            try:
                delay_replies(STRATEGY_PORTS, "30ms 10ms")
                for candidate in ("quic", "webrtc", "mosh", "obfs"):
                    wait_until_slow(path, candidate, 15)
                # ~30 probe rounds at the 1 s cadence: every candidate
                # measured repeatedly under the same noise.
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    assert "reselection:" not in path.read_text(), (
                        "identical noise switched transports:\n" + path.read_text()[-2000:]
                    )
                    # Keeps the echo target's 20 s read timeout alive.
                    veteran.sendall(b"keep")
                    assert recv_exact(veteran, 4) == b"keep"
                    time.sleep(2)
                rounds = len(re.findall(r"challenge: probing", path.read_text()))
                assert rounds >= 10, f"only {rounds} probe rounds ran, the case proves nothing"
                tcp_echo(34)
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in path.read_text()
            finally:
                undelay_replies()
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS symmetric_noise_does_not_switch: one noise band, no reselection, the veteran flows")


TESTS = [
    ("test_udp_reselect_after_ban_expiry", test_udp_reselect_after_ban_expiry),
    ("test_degraded_incumbent_switches_and_drains", test_degraded_incumbent_switches_and_drains),
    ("test_incumbent_drift_ramp_switches", test_incumbent_drift_ramp_switches),
    ("test_symmetric_noise_does_not_switch", test_symmetric_noise_does_not_switch),
]
