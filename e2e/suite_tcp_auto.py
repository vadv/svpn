"""TCP/auto group: RST delivery, idle teardown, TCP transports and auto fallback."""

import pathlib
import re
import select
import socket
import subprocess
import time

from _lib import (
    CLIENT,
    LOG_DIR,
    PEER,
    SERVER,
    SSH,
    assert_client_rst_delivery,
    cleanup_verified,
    command,
    recv_exact,
    session,
    ssh,
    tcp_echo,
    until,
)


def test_client_rst_delivery():
    for name, options in [
        ("mosh", ["--mimic", "mosh"]),
        ("tcp-ssh", ["--mimic", "ssh", "--tcp-port", "41034"]),
        ("tcp-none", ["--mimic", "none", "--tcp-port", "41035"]),
    ]:
        with session("rst-" + name, args=CLIENT + options) as (process, path):
            assert_client_rst_delivery()
            tcp_echo(9)
            assert "data path lost" not in path.read_text(), path.read_text()
        cleanup_verified(process)
        print(f"PASS client RST {name}: target socket closed, link remains usable")


def test_idle_tcp_teardown():
    configs = [
        ("mosh", ["--mimic", "mosh"]),
        ("tcp-none", ["--mimic", "none", "--tcp-port", "41036"]),
        ("auto-tcp", ["--tcp-port", "41037"]),
    ]
    rule = ["OUTPUT", "-d", SERVER, "-p", "udp", "-j", "DROP"]
    for name, options in configs:
        if name == "auto-tcp":
            command(["iptables", "-w", "-I"] + rule)
        try:
            with session("idle-tcp-" + name, args=CLIENT + options + ["--stats-interval", "1"]) as (
                process,
                path,
            ):
                remote = subprocess.Popen(
                    SSH + [f"python3 -u /e2e/idle_tcp.py {PEER}"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    assert select.select([remote.stdout], [], [], 8)[0], "idle target did not start"
                    assert remote.stdout.readline().strip() == "listening"
                    with (
                        socket.create_connection((PEER, 9002), timeout=5) as client,
                        socket.create_connection((PEER, 9002), timeout=5) as target,
                    ):
                        assert recv_exact(client, 5) == b"ready"
                        assert recv_exact(target, 5) == b"ready"

                        def active_flows(remote=remote):
                            assert process.poll() is None and remote.poll() is None
                            counts = re.findall(r"flows (\d+) active", path.read_text())
                            return int(counts[-1]) if counts else None

                        until(lambda: active_flows() == 2)
                        # Keep the sockets and verify the 60 s idle policy, not just eventual closure.
                        time.sleep(45)
                        assert active_flows() == 2, "TCP flows expired before the idle threshold"
                        time.sleep(16)
                        until(lambda: active_flows() == 0, seconds=14)
                        client.settimeout(4)
                        try:
                            client.sendall(b"resume")
                            received = client.recv(1)
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                        else:
                            raise AssertionError(f"idle client expected reset, received {received!r}")
                        remote.stdin.write("wake\n")
                        remote.stdin.flush()
                        output, _ = remote.communicate(timeout=8)
                        assert remote.returncode == 0 and "target reset" in output, output
                    tcp_echo(11)
                    assert process.poll() is None
                    assert "data path lost" not in path.read_text(), path.read_text()
                finally:
                    if remote.poll() is None:
                        try:
                            remote.communicate(timeout=6)
                        except subprocess.TimeoutExpired:
                            remote.kill()
                            remote.communicate(timeout=3)
            cleanup_verified(process)
            print(f"PASS idle TCP {name}: client and target receive reset on resumption; new flow works")
        finally:
            if name == "auto-tcp":
                command(["iptables", "-w", "-D"] + rule)


def test_tcp_transport():
    args = CLIENT + ["--mimic", "banner", "--tcp-port", "41020"]
    with session("tcp", args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert "tcp_remote" in log, "client did not open a TCP flow"
        assert "tcp_accept" in log, "server did not accept a TCP flow"
    cleanup_verified(process)
    print("PASS tcp_transport: session + data over TCP flow transport")


def test_tcp_ephemeral():
    # tcp-port 0 binds an ephemeral listener; Endpoints/Opened must announce
    # the actual port (previously the literal 0 reached the client).
    args = CLIENT + ["--mimic", "banner", "--tcp-port", "0"]
    with session("tcp-ephemeral", args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert "tcp_remote" in log and "tcp_accept" in log, log
    cleanup_verified(process)
    print("PASS tcp ephemeral: port 0 session carries data")


def test_tcp_udp_blocked():
    # TCP mode does not depend on UDP: with server OUTPUT UDP blocked
    # the session and flows work, and the control SSH stays alive (it is TCP itself).
    ssh("iptables -w -A OUTPUT -p udp -j DROP")
    try:
        args = CLIENT + ["--mimic", "banner", "--tcp-port", "41025"]
        with session("tcp-udp-blocked", args=args) as (process, path):
            tcp_echo(0)
            tcp_echo(1)
            assert "tcp_remote" in path.read_text(), "client did not open a TCP flow"
        cleanup_verified(process)
    finally:
        ssh("iptables -w -D OUTPUT -p udp -j DROP")
    print("PASS tcp_udp_blocked: TCP flows survive server-wide UDP drop")


def test_tcp_teardown():
    args = CLIENT + ["--mimic", "none", "--tcp-port", "41021"]
    with session("tcp-teardown", args=args) as (process, path):
        tcp_echo(0)
        assert "tcp_accept" in path.read_text(), "server did not accept a TCP flow"
    # cleanup_verified already checked: the svpn process on the server is gone, the client
    # TUN is removed and not recreated; TCP connections are closed by JoinSet::abort_all in Drop.
    cleanup_verified(process)
    assert ssh("ss -H -ltn 'sport = :41021'").stdout == "", "TCP listener port survived"
    assert '"svpn"' not in ssh("ss -H -tanp").stdout, "server TCP sockets survived"
    assert '"svpn"' not in command(["ss", "-H", "-tanp"]).stdout, "client TCP sockets survived"
    print("PASS tcp_teardown: listener closed, no svpn sockets on either side")


def test_tcp_l0_l1():
    # The L0/L1 difference is unit-level framing (the banner prefix in the byte stream of banner mode
    # and its absence in none: banner_then_frames_in_one_chunk, none_mode_rejects_banner_as_frame);
    # here both modes pass the full e2e.
    for name, camouflage, port in (("tcp-l0", "none", "41022"), ("tcp-l1", "banner", "41023")):
        args = CLIENT + ["--mimic", camouflage, "--tcp-port", port]
        with session(name, args=args) as (process, path):
            tcp_echo(0)
            tcp_echo(1)
            assert "tcp_remote" in path.read_text(), "client did not open a TCP flow"
        cleanup_verified(process)
    print("PASS tcp_l0_l1: none and banner camouflage both carry data end-to-end")


def test_tcp_camouflage_ssh():
    args = CLIENT + ["--mimic", "ssh", "--tcp-port", "41024"]
    with session("tcp-ssh", args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert "tcp_remote" in log, "client did not open a TCP flow"
        assert "tcp_accept" in log, "server did not accept a TCP flow"
    cleanup_verified(process)
    print("PASS tcp_camouflage_ssh: session + data over SSH-lookalike camouflage")


def test_auto_tcp_fallback():
    # A TCP round winner must serve user flows without another UDP scan.
    ssh("iptables -w -A INPUT -p udp -j DROP")
    try:
        args = CLIENT
        with session("auto-udp-blocked", args=args, ready_timeout=90) as (process, path):
            preparations = path.read_text().count("channel: trying")
            tcp_echo(0)
            until(lambda: "tcp_remote" in path.read_text(), seconds=60)
            assert path.read_text().count("channel: trying") == preparations, "first flow retried failed UDP"
            tcp_echo(1)
            log = path.read_text()
            assert log.count("channel: trying") == preparations, "second flow retried banned UDP"
            assert "tcp_remote" in log, "client did not fall back to TCP"
            assert "tcp_accept" in log, "server did not accept fallback flow"
            assert not re.search(r"session task failed[^\n]*cancelled", log), log
        cleanup_verified(process)
    finally:
        ssh("iptables -w -D INPUT -p udp -j DROP")
    print("PASS auto_tcp_fallback: blocked UDP falls back to TCP candidate in auto mode")


def test_auto_exhausted():
    # NoReady: one full round fails with live SSH; stop before creating TUN.
    ssh("iptables -w -A INPUT -p udp -j DROP")
    ssh("iptables -w -A INPUT -p tcp --dport 41030 -j DROP")
    try:
        args = CLIENT + ["--tcp-port", "41030"]
        path = LOG_DIR / "auto-exhausted.log"
        with path.open("w") as log:
            process = subprocess.Popen(args + ["--log-level", "debug"], stdout=subprocess.DEVNULL, stderr=log)
            try:

                def stopped_without_tun():
                    assert not pathlib.Path("/sys/class/net/svpn0").exists(), "TUN created before readiness"
                    return process.poll() is not None

                until(stopped_without_tun, seconds=120)
                assert process.returncode != 0, "client exited with zero code"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        log = path.read_text()
        assert "checking round failed" in log, log[-2000:]
        assert "no server available" in log, log[-2000:]
        assert "vpn: started" not in log, log[-2000:]
        for candidate in ("quic", "webrtc", "obfs", "mosh"):
            assert re.search(rf"\b{candidate}: \w+", log), log[-2000:]
        assert "tcp: probe timeout" in log, log[-2000:]
        cleanup_verified(process)
    finally:
        ssh("iptables -w -D INPUT -p tcp --dport 41030 -j DROP")
        ssh("iptables -w -D INPUT -p udp -j DROP")
    print("PASS auto_exhausted: failed round -> NoReady stop, no TUN, both sides clean")


TESTS = [
    ("test_client_rst_delivery", test_client_rst_delivery),
    ("test_idle_tcp_teardown", test_idle_tcp_teardown),
    ("test_tcp_transport", test_tcp_transport),
    ("test_tcp_ephemeral", test_tcp_ephemeral),
    ("test_tcp_udp_blocked", test_tcp_udp_blocked),
    ("test_tcp_teardown", test_tcp_teardown),
    ("test_tcp_l0_l1", test_tcp_l0_l1),
    ("test_tcp_camouflage_ssh", test_tcp_camouflage_ssh),
    ("test_auto_tcp_fallback", test_auto_tcp_fallback),
    ("test_auto_exhausted", test_auto_exhausted),
]
