"""UDP group: data path, fd limit, masquerade NAT, server port range and perf."""

import concurrent.futures
import json
import pathlib
import re
import socket
import subprocess
import time

from _lib import (
    CLIENT,
    LOCAL,
    LOG_DIR,
    PEER,
    SERVER,
    assert_client_rst_delivery,
    cleanup_verified,
    command,
    recv_exact,
    session,
    ssh,
    tcp_echo,
    until,
)


def test_data():
    default_before = command(["ip", "-j", "route", "show", "default"]).stdout
    dns_before = pathlib.Path("/etc/resolv.conf").read_bytes()
    with session("data") as (process, path):
        tun = json.loads(command(["ip", "-j", "addr", "show", "dev", "svpn0"]).stdout)[0]
        assert tun["mtu"] == 1280
        assert "POINTOPOINT" in tun["flags"]
        assert any(address.get("local") == LOCAL for address in tun["addr_info"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for _ in range(16):
                list(pool.map(tcp_echo, range(8)))
        counters = ssh("nstat -az TcpExtListenOverflows TcpExtListenDrops").stdout
        assert all(line.startswith("#") or line.split()[1] == "0" for line in counters.splitlines()), counters
        # v2 channels: one channel carries many flows; there are no per-flow UDP ports.
        log = path.read_text()
        requests = re.findall(r"flow_request id=(\d+)", log)
        server_opens = re.findall(r"flow_open role=server id=(\d+)", log)
        assert len(requests) == 128, len(requests)
        assert len(set(requests)) == 128, "flow ids must be unique"
        assert len(server_opens) == 128, len(server_opens)
        print("PASS TCP: 16 batches of eight concurrent flows over shared channels, half-close")
        with socket.create_connection((PEER, 9000), timeout=5) as stream:
            stream.sendall(b"before")
            assert stream.recv(6, socket.MSG_WAITALL) == b"before"
            ssh(f"python3 /e2e/forged_rst.py {stream.getsockname()[1]}")
            time.sleep(2.2)
            stream.sendall(b"after")
            assert stream.recv(5, socket.MSG_WAITALL) == b"after"
        print("PASS out-of-window TCP RST does not delete the VPN flow")

        assert_client_rst_delivery()
        print("PASS in-window TCP RST reaches the target socket within seconds")

        for size in (1, 17, 600, 1200):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                payload = b"U" * size
                for _ in range(2):
                    sock.sendto(payload, (PEER, 9000))
                    data, address = sock.recvfrom(2048)
                    assert data == payload and address == (PEER, 9000)
        print("PASS UDP: four flows and multiple packets per flow")

        command(["ping", "-n", "-c", "2", "-W", "2", PEER])
        command(["ping", "-n", "-c", "1", "-W", "2", "-M", "do", "-s", "1252", PEER])
        oversized = command(["ping", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", "1253", PEER], check=False)
        assert oversized.returncode != 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect((PEER, 9001))
            sock.send(b"closed port")
            try:
                sock.recv(128)
                raise AssertionError("expected ICMP port-unreachable")
            except ConnectionRefusedError:
                pass
        print("PASS ICMP: echo, full-MTU packet, oversize rejection and quoted UDP error")

        # v2: both sides log local_stats every 5 ticks;
        # the server's copy reaches the client log through the SSH tail.
        until(lambda: path.read_text().count("stats:") >= 2)
        assert re.search(r"rx_packets=[1-9]", path.read_text()), "missing traffic statistics"
        assert command(["ip", "-j", "route", "show", "default"]).stdout == default_before
        assert pathlib.Path("/etc/resolv.conf").read_bytes() == dns_before
        print("PASS statistics; default route and DNS unchanged")
        # Individual debug records may be dropped by the bounded logger.
        until(lambda: _flows_reclaimed(path.read_text(), len(requests)), seconds=270)
        print("PASS acknowledged FIN pairs: all 128 echo flows reclaimed after closing dwell")
    cleanup_verified(process)
    assert process.returncode == 0, path.read_text()
    print("PASS explicit stop: both TUNs, UDP sockets and server process removed")


def test_low_fd_limit():
    """Shared UDP channel: 70 flows fit within 64 fds and heartbeat stays alive.
    Auto may choose per-flow TCP, which needs one socket per flow instead."""
    wrapped = (
        ["bash", "-c", 'ulimit -Sn 64; ulimit -Hn 64; exec "$@"', "bash"]
        + CLIENT[:]
        + ["--mimic", "mosh", "--log-level", "debug"]
    )
    with session("low-fd", args=wrapped) as (process, path):

        def connect(_):
            try:
                stream = socket.create_connection((PEER, 9000), timeout=2)
                stream.sendall(b"fd-limit-probe")
                return stream
            except OSError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            streams = [stream for stream in pool.map(connect, range(70)) if stream is not None]
        try:
            assert len(streams) == 70, f"flows failed under fd limit: {len(streams)}"
            # Verify data right away: the echo server drops the stream after 20s idle.
            streams[0].sendall(b"-after")
            got = recv_exact(streams[0], 20)
            assert got == b"fd-limit-probe-after", repr(got)
            heartbeats = path.read_text().count("heartbeat received")
            assert heartbeats >= 1
            time.sleep(2.2)
            assert path.read_text().count("heartbeat received") > heartbeats, "heartbeat stopped"
            assert process.poll() is None, path.read_text()
            print(
                f"PASS low fd limit (mosh): all {len(streams)} flows live within 64 fds, heartbeat continues"
            )
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process)


NFT_RULES = """table inet svpn_masq {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 10.77.0.0/24 accept
  }
  chain masq {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/24 masquerade
  }
}
"""


def test_masquerade():
    # ip_forward is preconfigured in Compose; this fixture checks administrator-supplied nftables NAT.
    ssh(
        "mkdir -p /etc/nftables.d && cat > /etc/nftables.d/svpn.nft <<'NFT'\n"
        + NFT_RULES
        + "NFT\nnft -f /etc/nftables.d/svpn.nft"
    )
    assert "1" in ssh("sysctl -n net.ipv4.ip_forward").stdout.split()
    with session("masq") as (process, path):
        # The user routes the external service address into the TUN (routes are the OS's domain).
        command(["ip", "route", "replace", "172.30.77.4/32", "dev", "svpn0"])
        with socket.create_connection(("172.30.77.4", 9000), timeout=10) as stream:
            # The target sends the peer IP address and '\n' — read the whole frame.
            peer = recv_exact(stream, len(SERVER) + 1).strip()
            assert peer == SERVER.encode(), peer
            stream.sendall(b"masq-probe")
            assert recv_exact(stream, len(b"masq-probe")) == b"masq-probe"
        print("PASS masquerade: external service sees source=server IP, session alive")
    cleanup_verified(process)
    # The rules are shared across sessions and survive the stop.
    assert "svpn_masq" in ssh("nft list tables").stdout
    print("PASS masquerade: rules survive session stop")


def server_udp_ports():
    # v2: channels share sockets; QUIC loopback releases (127.0.0.1) are internal, not counted.
    out = ssh("ss -H -uanp | grep '\"svpn\"' || true").stdout
    return {
        int(line.split()[3].rsplit(":", 1)[1])
        for line in out.splitlines()
        if line.strip() and not line.split()[3].startswith("127.0.0.1:")
    }


def test_udp_port_range():
    with session("ports", args=CLIENT + ["--udp-port-range", "41000-41003"]) as (process, path):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(tcp_echo, range(4)))
        ports = server_udp_ports()
        # v2 channels: one channel carries many flows; the whole range is not taken.
        assert ports and ports <= {41000, 41001, 41002, 41003}, f"flow ports left the range: {ports}"
        # The FIN dwell keeps the ports busy; once released, the second wave takes them again.
        time.sleep(17)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(tcp_echo, range(4, 8)))
        ports = server_udp_ports()
        assert ports and ports <= {41000, 41001, 41002, 41003}, f"ports left the range: {ports}"
        print("PASS port range: server flow ports stay within 41000-41003 and are reused")
    cleanup_verified(process)
    print("PASS port range: session cleaned up")


def test_perf():
    base = [
        "svpn",
        "perf",
        "--server",
        SERVER,
        "--ssh-user",
        "root",
        "--ssh-identity",
        "/keys/client",
        "--peer-tun-name",
        "svpn0",
        "--tun-name",
        "svpn0",
    ]

    def run_perf(extra, timeout=90, mimic="mosh"):
        log = LOG_DIR / f"perf-{mimic}-{time.monotonic_ns()}.log"
        with log.open("w") as err:
            result = subprocess.run(
                base + ["--mimic", mimic] + extra,
                text=True,
                stdout=subprocess.PIPE,
                stderr=err,
                timeout=timeout,
            )
        return result, log

    def both_clean():
        assert not pathlib.Path("/sys/class/net/svpn0").exists(), "client TUN survived"
        until(
            lambda: ssh("pgrep -x svpn", check=False).returncode == 1
            and not any(item["ifname"] == "svpn0" for item in json.loads(ssh("ip -j link show").stdout))
        )

    # Download: JSON on stdout, segments/RTT/summary, exit 0, both sides clean.
    result, log = run_perf(["-t", "3", "--json"])
    assert result.returncode == 0, log.read_text()
    report = json.loads(result.stdout)
    assert report["ready_ms"] < 20000, report
    assert report["end_summary"]["sum"]["median"] > 0, report
    assert report["intervals"] and report["intervals"][0]["rtt_p50_ms"] is not None, report
    both_clean()

    # Upload (-R) by time: text report to stderr.
    result, log = run_perf(["-R", "-t", "3"])
    assert result.returncode == 0, log.read_text()
    assert "Mbps" in log.read_text()
    both_clean()

    # Bytes instead of time (-n): a quick one-shot exit.
    result, log = run_perf(["-n", "2M"], timeout=60)
    assert result.returncode == 0, log.read_text()
    both_clean()

    # W01: the old WebRTC pump delivered ~0.22 Mbit/s even without loss and RTT.
    result, log = run_perf(["-t", "6", "-i", "2", "-l", "16K", "--json"], mimic="webrtc")
    assert result.returncode == 0, log.read_text()
    report = json.loads(result.stdout)
    assert report["end_summary"]["sum"]["mean"] > 5, report
    both_clean()

    # W01: SCTP congestion at ~40 ms RTT must not close all four flows.
    command(["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "20ms"])
    server_delay = False
    try:
        ssh("tc qdisc add dev eth0 root netem delay 20ms")
        server_delay = True
        result, log = run_perf(
            ["-P", "4", "-t", "12", "-i", "3", "-l", "1M", "--json"], timeout=30, mimic="webrtc"
        )
        assert result.returncode == 0, log.read_text()
        report = json.loads(result.stdout)
        assert report["end_summary"]["sum"]["mean"] > 1, report
        assert "channel_failed" not in log.read_text(), log.read_text()
        # Each of the four flows must transfer on its own: the aggregate hides
        # three stalled streams behind one live stream. Look at the intervals after warm-up.
        intervals = report["intervals"][1:]
        assert intervals, report
        per_stream = [sum(row["streams_mbit"][i] for row in intervals) for i in range(4)]
        assert all(s > 0 for s in per_stream), per_stream
    finally:
        try:
            if server_delay:
                ssh("tc qdisc del dev eth0 root")
        finally:
            command(["tc", "qdisc", "del", "dev", "eth0", "root"])
    both_clean()

    # Failure: unreachable SSH port -> non-zero exit with the reason in stderr, nothing leaked.
    result, log = run_perf(["--ssh-port", "1", "-t", "2"], timeout=60)
    assert result.returncode != 0
    assert "svpn:" in log.read_text(), log.read_text()
    both_clean()
    print("PASS perf: download JSON, upload -R, -n bytes, WebRTC throughput/P4 RTT, ssh failure exit")


def _flows_reclaimed(log, minimum):
    latest = {}
    for match in re.finditer(
        r"(?m)^t\+\s*[\d.]+s (\[server\] )?heartbeat received stats=Stats \{[^\n]*"
        r"opened_flows: (\d+), open_failed_flows: (\d+), closed_flows: (\d+), active_flows: (\d+)",
        log,
    ):
        latest[bool(match[1])] = tuple(map(int, match.groups()[1:]))
    return len(latest) == 2 and all(
        opened >= minimum and failed == 0 and closed == opened and active == 0
        for opened, failed, closed, active in latest.values()
    )


TESTS = [
    ("test_data", test_data),
    ("test_low_fd_limit", test_low_fd_limit),
    ("test_masquerade", test_masquerade),
    ("test_udp_port_range", test_udp_port_range),
    ("test_perf", test_perf),
]
