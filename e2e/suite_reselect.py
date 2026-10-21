"""EPIC-016 re-selection: ban expiry moves new flows back to UDP while TCP flows survive."""

import os
import re
import socket
import time

from _lib import PEER, cleanup_verified, recv_exact, session, ssh, tcp_echo, until

# SVPN_TEST_BAN_BACKOFF_SECS (selector.rs ban_backoff_start) shrinks the first
# ban so the expiry-driven challenge fits the test budget.
ENV = dict(os.environ, SVPN_TEST_BAN_BACKOFF_SECS="3")


def tcp_flow_ids(log):
    return set(
        re.findall(
            r"flow_open role=server id=(\d+)(?: channel=\d+)? transport=tcp",
            log,
        )
    )


def test_udp_reselect_after_ban_expiry():
    # S2 criterion: block UDP at start -> tcp, unblock -> new flows move to
    # UDP, the TCP flow opened before the switch keeps flowing.
    ssh("iptables -w -A INPUT -p udp -j DROP")
    try:
        with session("reselect", args=None, env=ENV, ready_timeout=90) as (process, path):
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
                    if re.search(r"challenge: \w+ wins \(p90", log):
                        break
                    time.sleep(2)
                else:
                    raise AssertionError("no challenger won after UDP was unblocked:\n" + log[-2000:])

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


TESTS = [
    ("test_udp_reselect_after_ban_expiry", test_udp_reselect_after_ban_expiry),
]
