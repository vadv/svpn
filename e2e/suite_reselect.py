"""Re-selection: ban expiry moves new flows back to UDP while TCP flows survive."""

import os
import re
import socket
import time

from _lib import CLIENT, PEER, cleanup_verified, recv_exact, session, ssh, tcp_echo, until

# SVPN_TEST_BAN_BACKOFF_SECS (selector.rs ban_backoff_start) shrinks the first
# ban so the expiry-driven challenge fits the test budget. The remeasure
# cadence gates every challenge; 1 s opens it right away.
ENV = dict(os.environ, SVPN_TEST_BAN_BACKOFF_SECS="3")
ARGS = CLIENT + ["--remeasure-interval", "1"]


def tcp_flow_ids(log):
    return set(
        re.findall(
            r"flow_open role=server id=(\d+)(?: channel=\d+)? transport=tcp",
            log,
        )
    )


def test_udp_reselect_after_ban_expiry():
    # S2 criterion: block UDP at start -> tcp, unblock -> new flows move to
    # UDP, the TCP flow opened before the switch keeps flowing. S3: the
    # switch needs two consecutive winning rounds, so the first challenge
    # only arms the retry and the second one lands the reselection.
    ssh("iptables -w -A INPUT -p udp -j DROP")
    try:
        with session("reselect", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
            # One established TCP flow must survive the transport switch; TCP
            # idle teardown is 60 s, so keep it busy while the challenge runs.
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
                        r"flow_open role=server id=\d+(?: channel=\d+)? "
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
    # S3 criterion: the UDP incumbent degrades -> a challenger beats it by
    # the margin in two consecutive rounds -> reselection; the flow opened
    # before the switch keeps flowing on the draining channel.
    with session("degrade", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=20) as veteran:
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(
                lambda: re.search(
                    r"flow_open role=server id=\d+(?: channel=\d+)? "
                    r"transport=(mosh|quic|webrtc|obfs)",
                    path.read_text(),
                ),
                seconds=30,
            )
            log = path.read_text()
            adopted = re.search(r"transport=(mosh|quic|webrtc|obfs)", log).group(1)
            strategies, ports = re.search(r"serve: strategies=([\w+]+) udp_ports=([\d,]+)", log).groups()
            port = dict(zip(strategies.split("+"), ports.split(",")))[adopted]
            # Delay only the incumbent's replies: p90 degrades without loss,
            # so the veteran's TCP flow survives on the draining channel.
            ssh(
                "tc qdisc add dev eth0 root handle 1: prio"
                " && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 150ms"
                f" && tc filter add dev eth0 protocol ip parent 1:0 prio 3"
                f" u32 match ip sport {port} 0xffff flowid 1:3"
            )
            try:
                switched = None
                deadline = time.monotonic() + 240
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
                until(
                    lambda: re.search(
                        r"flow_open role=server id=\d+(?: channel=\d+)? transport=" + winner,
                        path.read_text(),
                    ),
                    seconds=15,
                )
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in path.read_text()
            finally:
                ssh("tc qdisc del dev eth0 root", check=False)
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS degraded_incumbent_switches_and_drains: margin winner takes over, the veteran drains")


def ramp_qdisc(port, delay_ms):
    # Replace the root qdisc wholesale: repeated `change` on a prio+netem
    # stack is brittle across iproute2 versions.
    ssh("tc qdisc del dev eth0 root", check=False)
    ssh(
        "tc qdisc add dev eth0 root handle 1: prio"
        f" && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay {delay_ms}ms"
        f" && tc filter add dev eth0 protocol ip parent 1:0 prio 3"
        f" u32 match ip sport {port} 0xffff flowid 1:3"
    )


def test_incumbent_drift_ramp_switches():
    # EPIC-017 e2e: delay on the incumbent ramped in small steps must still
    # end in a reselection once the smoothed estimates separate — and the
    # ramp must not break live traffic on the way there.
    with session("drift", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=20) as veteran:
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(
                lambda: re.search(
                    r"flow_open role=server id=\d+(?: channel=\d+)? "
                    r"transport=(mosh|quic|webrtc|obfs)",
                    path.read_text(),
                ),
                seconds=30,
            )
            log = path.read_text()
            adopted = re.search(r"transport=(mosh|quic|webrtc|obfs)", log).group(1)
            strategies, ports = re.search(r"serve: strategies=([\w+]+) udp_ports=([\d,]+)", log).groups()
            port = dict(zip(strategies.split("+"), ports.split(",")))[adopted]
            try:
                # Three small steps beat one spike: each level must sit in
                # the EWMA window before the next one lands.
                for step in (40, 90, 150):
                    ramp_qdisc(port, step)
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
                until(
                    lambda: re.search(
                        r"flow_open role=server id=\d+(?: channel=\d+)? transport=" + winner,
                        path.read_text(),
                    ),
                    seconds=15,
                )
                veteran.sendall(b"after")
                assert recv_exact(veteran, 5) == b"after"
                assert "data path lost" not in path.read_text()
            finally:
                ssh("tc qdisc del dev eth0 root", check=False)
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS incumbent_drift_ramp_switches: ramped delay ends in reselection")


def test_symmetric_noise_does_not_switch():
    # EPIC-017 e2e: identical delay with jitter on every strategy port puts
    # all candidates inside one noise band — no reselection may land while
    # probes keep running.
    with session("noise", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        until(
            lambda: re.search(
                r"flow_open role=server id=\d+(?: channel=\d+)? "
                r"transport=(mosh|quic|webrtc|obfs)",
                path.read_text(),
            ),
            seconds=30,
        )
        try:
            ssh(
                "tc qdisc add dev eth0 root handle 1: prio"
                " && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 30ms 10ms"
            )
            for port in range(60000, 60010):
                ssh(
                    f"tc filter add dev eth0 protocol ip parent 1:0 prio 3"
                    f" u32 match ip sport {port} 0xffff flowid 1:3"
                )
            # ~30 probe rounds at the 1 s cadence: every candidate measured
            # repeatedly under the same noise.
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                assert "reselection:" not in path.read_text(), (
                    "identical noise switched transports:\n" + path.read_text()[-2000:]
                )
                time.sleep(2)
            rounds = len(re.findall(r"challenge: probing", path.read_text()))
            assert rounds >= 10, f"only {rounds} probe rounds ran, the case proves nothing"
            tcp_echo(34)
            assert "data path lost" not in path.read_text()
        finally:
            ssh("tc qdisc del dev eth0 root", check=False)
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS symmetric_noise_does_not_switch: one noise band, no reselection")


TESTS = [
    ("test_udp_reselect_after_ban_expiry", test_udp_reselect_after_ban_expiry),
    ("test_degraded_incumbent_switches_and_drains", test_degraded_incumbent_switches_and_drains),
    ("test_incumbent_drift_ramp_switches", test_incumbent_drift_ramp_switches),
    ("test_symmetric_noise_does_not_switch", test_symmetric_noise_does_not_switch),
]
