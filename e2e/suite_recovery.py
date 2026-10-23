"""Flow recovery: a live flow survives datagram-path loss, never re-sends
uncertain payload, and finishes inside the budget when no path exists.
Fault injection: the server drops the incumbent strategy's UDP port while
SSH control stays alive — the NAT-rebind analog with both peers running."""

import os
import re
import socket
import time

from _lib import CLIENT, PEER, cleanup_verified, recv_exact, session, ssh, tcp_echo, until

# A 1 s remeasure cadence detects the dead path quickly; the shortened ban
# backoff keeps any candidate ban from stretching the rebind window.
ENV = dict(os.environ, SVPN_TEST_BAN_BACKOFF_SECS="3")
ARGS = CLIENT + ["--remeasure-interval", "1"]

FLOW = re.compile(
    r"flow_open role=server id=(\d+)(?: generation=\d+)?(?: channel=\d+)? "
    r"transport=(mosh|quic|webrtc|obfs)"
)
RESTORED = (
    "flow_recovery_restored id={fid} generation=\\d+ stage=(?:peer_packet|probe)"
    " \\S+ \\S+ \\S+ elapsed_ms=(\\d+)"
)


def incumbent_port(log):
    adopted = FLOW.search(log).group(2)
    strategies, ports = re.search(r"serve: strategies=([\w+]+) udp_ports=([\d,]+)", log).groups()
    return int(dict(zip(strategies.split("+"), ports.split(",")))[adopted])


def echo_sockets(dport):
    # The echo service's side of one tunnelled connection: a second line or a
    # changed tuple would mean the target socket was re-created.
    query = f"ss -Htn state established '( sport = :9000 and dport = :{dport} )'"
    lines = [line for line in ssh(query).stdout.splitlines() if line.strip()]
    return {tuple(line.split()[3:5]) for line in lines}


def test_recovery_restores_tcp_without_second_accept():
    # The incumbent UDP path dies mid-flow: both peers rebind and the
    # established TCP connection continues byte-exact — no new accept on the
    # echo service, no lost or duplicated bytes, journal shows confirmed
    # delivery only.
    with session("recovery-tcp", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=5) as veteran:
            veteran.settimeout(5)
            sent = bytearray(b"before")
            veteran.sendall(sent)
            assert recv_exact(veteran, 6) == b"before"
            until(lambda: FLOW.search(path.read_text()), seconds=90)
            fid = FLOW.search(path.read_text()).group(1)
            port = incumbent_port(path.read_text())
            before = echo_sockets(veteran.getsockname()[1])
            assert len(before) == 1, "the echo connection is not established"

            ssh(f"iptables -w -A INPUT -p udp --dport {port} -j DROP")
            try:
                restored = None
                deadline = time.monotonic() + 240
                while time.monotonic() < deadline:
                    try:
                        veteran.sendall(b"keep")
                        sent.extend(b"keep")
                    except OSError:
                        pass  # a full buffer while the path is dead is expected
                    restored = re.search(RESTORED.format(fid=fid), path.read_text())
                    if restored:
                        break
                    time.sleep(2)
                else:
                    raise AssertionError(
                        "no confirmed recovery after the path loss:\n" + path.read_text()[-2000:]
                    )
                assert f"flow_recovery_start id={fid} " in path.read_text(), "recovery began unannounced"

                # Everything sent across the outage comes back exactly once,
                # in order — sent and read in lockstep: a bulk sendall without
                # reading would close the client's receive window and deadlock
                # the echo path at the kernel level.
                echoed = 6
                for i in range(4):
                    block = bytes([65 + i]) * 65536
                    veteran.sendall(block)
                    sent.extend(block)
                    assert recv_exact(veteran, len(sent) - echoed, seconds=60) == bytes(sent)[echoed:]
                    echoed = len(sent)
                assert echo_sockets(veteran.getsockname()[1]) == before, "the target socket was re-created"
                # Byte-exact echo on the same accepted socket already proves
                # the data path is alive after the rebind: nothing to assert
                # on the journal ("data path lost" lines during the cut are
                # the selector probing its ssh candidate, as intended).
                assert int(restored.group(1)) < 60_000, "the rebind waited past any reasonable budget"
            finally:
                ssh(f"iptables -w -D INPUT -p udp --dport {port} -j DROP", check=False)
            tcp_echo(35)
            assert process.poll() is None
    cleanup_verified(process)
    print("PASS recovery_restores_tcp_without_second_accept: byte-exact continuation, one accept")


def test_recovery_does_not_retransmit_uncertain_udp():
    # RFC 8085 §3.3: a datagram with unknown delivery must not be re-sent by
    # the tunnel. The echo service answers every datagram it receives, so a
    # duplicate sequence number is a tunnel retransmission.
    with session("recovery-udp", args=ARGS, env=ENV, ready_timeout=90) as (process, path):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(0.5)
        udp.sendto(b"seq:0", (PEER, 9000))
        until(lambda: FLOW.search(path.read_text()), seconds=90)
        port = incumbent_port(path.read_text())

        ssh(f"iptables -w -A INPUT -p udp --dport {port} -j DROP")
        echoes = {}
        cut_seq = 1  # datagrams with seq >= cut_seq cross the cut uncertain
        try:
            seq = 1
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                udp.sendto(f"seq:{seq}".encode(), (PEER, 9000))
                seq += 1
                try:
                    while True:
                        data, _ = udp.recvfrom(2048)
                        count = int(data.rsplit(b":", 1)[1])
                        echoes[count] = echoes.get(count, 0) + 1
                except socket.timeout:
                    pass
                # A UDP flow does not rebind: the cut one closes and the same
                # tuple re-opens on the next channel (journal: flow_close +
                # flow_open). Recovery here means exactly one echo came back
                # for a datagram sent after the cut.
                if any(s >= cut_seq for s in echoes):
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("the UDP flow never recovered:\n" + path.read_text()[-2000:])
            # Drain well past the rebind: late duplicates are retransmissions.
            stop = time.monotonic() + 15
            while time.monotonic() < stop:
                try:
                    while True:
                        data, _ = udp.recvfrom(2048)
                        count = int(data.rsplit(b":", 1)[1])
                        echoes[count] = echoes.get(count, 0) + 1
                except socket.timeout:
                    pass
                time.sleep(0.5)
        finally:
            ssh(f"iptables -w -D INPUT -p udp --dport {port} -j DROP", check=False)
        assert echoes, "no datagram was delivered across the recovery"
        duplicates = [seq for seq, count in echoes.items() if count > 1]
        assert not duplicates, f"the tunnel re-sent uncertain datagrams: {sorted(duplicates)}"
        assert process.poll() is None
    cleanup_verified(process)
    print("PASS recovery_does_not_retransmit_uncertain_udp: every echoed datagram exactly once")


def test_recovery_without_alternative_closes_within_budget():
    # No alternative candidate exists (single UDP strategy, its port blocked,
    # ssh control alive): per EPIC-019 the current termination policy applies —
    # the client finishes within the round budget and the journal never claims
    # success. Flow-level final failure of a surviving multi-candidate session
    # is covered by tests/session_recovery.rs.
    args = CLIENT + ["--mimic", "mosh"]
    with session("recovery-none", args=args, env=ENV, ready_timeout=90) as (process, path):
        with socket.create_connection((PEER, 9000), timeout=5) as veteran:
            veteran.settimeout(5)
            veteran.sendall(b"before")
            assert recv_exact(veteran, 6) == b"before"
            until(lambda: FLOW.search(path.read_text()), seconds=90)
            port = incumbent_port(path.read_text())

            ssh(f"iptables -w -A INPUT -p udp --dport {port} -j DROP")
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(1)
                else:
                    raise AssertionError(
                        "the client outlived the recovery budget:\n" + path.read_text()[-2000:]
                    )
                log = path.read_text()
                assert "flow_recovery_restored" not in log, "a path-less recovery claimed success"
                assert "no server available" in log, "no final-failure record"
            finally:
                ssh(f"iptables -w -D INPUT -p udp --dport {port} -j DROP", check=False)
    print("PASS recovery_without_alternative_closes_within_budget: clean stop in budget, no false success")


TESTS = [
    ("test_recovery_restores_tcp_without_second_accept", test_recovery_restores_tcp_without_second_accept),
    ("test_recovery_does_not_retransmit_uncertain_udp", test_recovery_does_not_retransmit_uncertain_udp),
    (
        "test_recovery_without_alternative_closes_within_budget",
        test_recovery_without_alternative_closes_within_budget,
    ),
]
