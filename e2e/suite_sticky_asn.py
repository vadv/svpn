"""Sticky-asn group: destination pinning, balance regression, failover and restart restore."""

import ipaddress
import json
import pathlib
import re
import signal
import socket

from _lib import (
    CLIENT_POOL,
    PEER,
    SERVER,
    SERVER2,
    cleanup_verified,
    command,
    session,
    ssh,
    ssh_to,
    tcp_echo,
    until,
)

HOSTS = (SERVER, SERVER2)
CSV = pathlib.Path("/tmp/e2e-asn.csv")
COUNTRY_CSV = pathlib.Path("/tmp/e2e-country.csv")
STATE = pathlib.Path("/var/lib/svpn/exit-state.json")
TARGET = "172.30.77.4"
LOCAL_TARGET = "172.31.77.4"
BY_TARGET = "172.32.77.5"
OFF_TARGET = "172.31.77.5"
# One /17 block per row: 131072 synthetic rows pass Geo::load's 100k-row floor and give
# every subnet a distinct ASN, so rendezvous picks differ across destination groups.
HOST_BITS = 15
ROWS = 1 << (32 - HOST_BITS)
FILLER_ASN = 2_000_000
MASQUERADE_RULES = """table inet svpn_masq {
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

_geo_asn = None
_country_ready = False


def _dotted(value):
    return f"{value >> 24}.{value >> 16 & 255}.{value >> 8 & 255}.{value & 255}"


def write_geo():
    global _geo_asn
    if _geo_asn is None:
        peer_row = int(ipaddress.IPv4Address(PEER)) >> HOST_BITS
        _geo_asn = 64512 + peer_row
        mask = (1 << HOST_BITS) - 1
        with CSV.open("w") as out:
            for row in range(ROWS):
                start = row << HOST_BITS
                asn = _geo_asn if row == peer_row else FILLER_ASN + row
                out.write(f'"{_dotted(start)}","{_dotted(start | mask)}",{asn},"synthetic"\n')
    return _geo_asn


def write_country():
    global _country_ready
    if _country_ready:
        return
    local_rows = {
        int(ipaddress.IPv4Address(address)) >> HOST_BITS for address in (TARGET, LOCAL_TARGET, OFF_TARGET)
    }
    by_row = int(ipaddress.IPv4Address(BY_TARGET)) >> HOST_BITS
    mask = (1 << HOST_BITS) - 1
    with COUNTRY_CSV.open("w") as out:
        for row in range(ROWS):
            start = row << HOST_BITS
            country = "RU" if row in local_rows else "BY" if row == by_row else "DE"
            out.write(f'"{_dotted(start)}","{_dotted(start | mask)}",{country}\n')
    _country_ready = True


def enable_target_masquerade(host=SERVER):
    # Remote exits need the administrator-provided NAT fixture; unlike the
    # tunnel peer, the external target has no route back to 10.77.0.0/24.
    command(
        ssh_to(host)
        + [
            "mkdir -p /etc/nftables.d && cat > /etc/nftables.d/svpn.nft <<'NFT'\n"
            + MASQUERADE_RULES
            + "NFT\nnft -f /etc/nftables.d/svpn.nft"
        ]
    )


def country_args(local_exit=False):
    write_geo()
    write_country()
    args = [
        "svpn",
        "multi",
        "--server",
        f"{SERVER},user=root,identity=/keys/client,countries=RU",
        "--server",
        f"{SERVER2},user=root,identity=/keys/client,countries=DE",
        "--peer-tun-name",
        "svpn0",
        "--tun-name",
        "svpn0",
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        str(CSV),
        "--country-db",
        str(COUNTRY_CSV),
        "--exit-state",
        str(STATE),
        "--stats-interval",
        "1",
    ]
    if local_exit:
        args += [
            "--local-exits",
            "RU,BY",
            "--up-command",
            "/hooks/client-up eth0 172.30.77.2 172.30.77.5",
            "--down-command",
            "/hooks/client-down eth0 172.30.77.2 172.30.77.5",
            "--server-up",
            "/hooks/server-up eth0",
            "--server-down",
            "/hooks/server-down",
        ]
    return args


def sticky_args():
    write_geo()
    return CLIENT_POOL + [
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        str(CSV),
        "--exit-state",
        str(STATE),
        "--stats-interval",
        "1",
    ]


def fresh_state():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.unlink(missing_ok=True)


def opened(path):
    # One-shot flow lines may be dropped by the relay; the heartbeat stats repeat and converge.
    counts = {}
    for host in HOSTS:
        found = re.findall(rf"\[server {re.escape(host)}\][^\n]*opened_flows: (\d+)", path.read_text())
        counts[host] = int(found[-1]) if found else 0
    return counts


def delta(path, baseline):
    counts = opened(path)
    return {host: counts[host] - baseline[host] for host in HOSTS}


def sticky_counters(path):
    found = re.findall(r"sticky: lookup hit (\d+) / miss (\d+) \| failover moves (\d+)", path.read_text())
    assert found, "sticky counters missing from the stats report"
    return tuple(int(value) for value in found[-1])


def sticky_counters_now(path, expected):
    """Non-raising predicate for until(): the periodic sticky report lags the flow
    heartbeat, so poll until the counters converge instead of trusting a snapshot."""
    found = re.findall(r"sticky: lookup hit (\d+) / miss (\d+) \| failover moves (\d+)", path.read_text())
    return bool(found) and tuple(int(value) for value in found[-1]) == expected


def pinned_owner(path, baseline, count):
    """The server that owns every one of `count` new flows, once counters converge."""
    counts = delta(path, baseline)
    return counts if sorted(counts.values()) == [0, count] else None


def kill_and_degrade(process, path, owner):
    """Kill the owner's serve binary, wait for the degraded state; returns the
    pre-kill count of steady 2/2 lines for the later rejoin wait (the rejoin
    may land while post-kill flows are still being verified)."""
    assert process.poll() is None, path.read_text()
    steady = path.read_text().count("serving (2/2 servers ready,")
    degraded = path.read_text().count("serving (1/2 servers ready,")
    command(ssh_to(owner) + ["pkill", "-x", "svpn"])
    until(lambda: path.read_text().count("serving (1/2 servers ready,") > degraded, seconds=15)
    # A checking owner intentionally lends new flows to a reserve without
    # migrating the sticky group. Wait for the actual failed/backoff state
    # before testing failover persistence.
    until(lambda: f"vpn[{owner}]: link failed" in path.read_text(), seconds=15)
    return steady


def wait_rejoined(path, steady):
    until(lambda: path.read_text().count("serving (2/2 servers ready,") > steady, seconds=45)


def test_sticky_dst():
    fresh_state()
    with session("sticky-dst", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        assert f"geo database {CSV}: {ROWS} IPv4 ranges" in path.read_text()
        baseline = opened(path)
        for index in range(10):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 10), seconds=15)
        until(lambda: sticky_counters_now(path, (9, 1, 0)), seconds=15)
        hit, miss, moves = sticky_counters(path)
        assert (hit, miss, moves) == (9, 1, 0), (hit, miss, moves)
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky destination: 10 flows to one dst:port exit via one server (9 hits / 1 miss)")


def test_balance_diff():
    write_geo()
    args = CLIENT_POOL + ["--exit-policy", "balance", "--geo-db", str(CSV)]
    with session("sticky-balance", args=args, server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        assert "geo-db set without exit-policy sticky-asn — ignoring" in path.read_text()
        assert "sticky: lookup" not in path.read_text(), "balance must not group destinations"
        baseline = opened(path)
        for index in range(12):
            tcp_echo(index)
        until(
            lambda: min(delta(path, baseline).values()) >= 4 and sum(delta(path, baseline).values()) == 12,
            seconds=15,
        )
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS balance regression: geo-db ignored, 12 flows still spread by flow key over both servers")


def test_failover_move():
    fresh_state()
    with session("sticky-failover", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(4):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 4), seconds=15)
        counts = delta(path, baseline)
        owner = SERVER if counts[SERVER] else SERVER2
        spare = SERVER2 if owner == SERVER else SERVER
        steady = kill_and_degrade(process, path, owner)
        alive = opened(path)[spare]
        for index in range(4, 10):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - alive == 6 and opened(path)[owner] == 0, seconds=30)
        wait_rejoined(path, steady)
        settled = opened(path)[spare]
        for index in range(10, 16):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - settled == 6 and opened(path)[owner] == 0, seconds=20)
        until(lambda: sticky_counters_now(path, (14, 2, 1)), seconds=15)
        assert sticky_counters(path)[2] == 1, "exactly one failover move expected"
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky failover: killed owner's group moves to the next exit and stays after rejoin")


def test_restart_restore():
    asn = write_geo()
    fresh_state()
    with session("sticky-restart-1", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(4):
            tcp_echo(index)
        until(lambda: pinned_owner(path, baseline, 4), seconds=15)
        counts = delta(path, baseline)
        owner = SERVER if counts[SERVER] else SERVER2
        spare = SERVER2 if owner == SERVER else SERVER
        kill_and_degrade(process, path, owner)
        for index in range(4, 8):
            tcp_echo(index)
        until(lambda: opened(path)[spare] - baseline[spare] == 4 and opened(path)[owner] == 0, seconds=30)
    # Clean stop: the client flushes the failover transition to /var/lib/svpn.
    cleanup_verified(process, server_hosts=HOSTS)
    persisted = json.loads(STATE.read_text())
    # Persisted identity is host:port (spec); the default ssh port is 22.
    assert persisted == {"version": 2, "country": {}, "asn": {str(asn): f"{spare}:22"}}, persisted
    with session("sticky-restart-2", args=sticky_args(), server_hosts=HOSTS, ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        baseline = opened(path)
        for index in range(6):
            tcp_echo(index)
        until(
            lambda: pinned_owner(path, baseline, 6) and pinned_owner(path, baseline, 6)[spare] == 6,
            seconds=15,
        )
    cleanup_verified(process, server_hosts=HOSTS)
    print("PASS sticky restart: persisted exit state restores the failed-over owner, no snap-back")


def local_opened(path):
    found = re.findall(r"local-exit: opened (\d+) / failed (\d+) / closed (\d+)", path.read_text())
    return tuple(int(value) for value in found[-1]) if found else None


def ping_local(destination):
    command(["ping", "-n", "-c", "1", "-W", "2", destination])


def target_tcp_echo(index, destination=TARGET, timeout=15):
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


def udp_echo(peer, payload=b"direct-udp"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(15)
        sock.sendto(payload, (peer, 9000))
        data, _ = sock.recvfrom(65535)
    assert data == payload


def shared_country_args():
    return [
        f"{value.split(',', 1)[0]},user=root,identity=/keys/client,countries=RU"
        if value.startswith((f"{SERVER},", f"{SERVER2},"))
        else value
        for value in country_args()
    ]


def test_country_asn_scope():
    fresh_state()
    enable_target_masquerade()
    try:
        with session("country-asn", args=country_args(), server_hosts=HOSTS, ready_timeout=20) as (
            process,
            path,
        ):
            until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
            command(["ip", "route", "replace", f"{TARGET}/32", "dev", "svpn0"])
            command(["ip", "route", "replace", f"{PEER}/32", "dev", "svpn0"])
            baseline = opened(path)
            source = target_tcp_echo(0)
            assert source == SERVER, source
            tcp_echo(1, peer=PEER)
            until(lambda: delta(path, baseline) == {SERVER: 1, SERVER2: 1}, seconds=20)
        cleanup_verified(process, server_hosts=HOSTS)
    finally:
        ssh("nft delete table inet svpn_masq", check=False)
    fresh_state()
    enable_target_masquerade()
    enable_target_masquerade(SERVER2)
    try:
        with session(
            "country-asn-shared", args=shared_country_args(), server_hosts=HOSTS, ready_timeout=20
        ) as (
            process,
            path,
        ):
            until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
            command(["ip", "route", "replace", f"{TARGET}/32", "dev", "svpn0"])
            owner = target_tcp_echo(10)
            for index in range(11, 16):
                assert target_tcp_echo(index) == owner
            spare = SERVER2 if owner == SERVER else SERVER
            steady = kill_and_degrade(process, path, owner)
            assert target_tcp_echo(16) == spare
            wait_rejoined(path, steady)
            assert target_tcp_echo(17) == spare
        cleanup_verified(process, server_hosts=HOSTS)
    finally:
        ssh("nft delete table inet svpn_masq", check=False)
        command(ssh_to(SERVER2) + ["nft delete table inet svpn_masq"], check=False)
    print("PASS country+ASN: shared-country owner and constrained failover stay stable")


def remove_option(args, option):
    index = args.index(option)
    del args[index : index + 2]


def test_local_exits_hook_optional():
    for mode in ("none", "down-only"):
        fresh_state()
        command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0"])
        args = country_args(local_exit=True)
        remove_option(args, "--up-command")
        if mode == "none":
            remove_option(args, "--down-command")
        with session(
            "local-hooks-" + mode,
            args=args,
            server_hosts=HOSTS,
            client_route=False,
            server_route=False,
            ready_timeout=20,
        ) as (process, path):
            until(lambda: "local-exit: ready" in path.read_text(), seconds=15)
        cleanup_verified(process, server_hosts=HOSTS)
    print("PASS local-exit optional hooks: no-up and down-only startup and cleanup")


def test_local_exits_and_vpn():
    fresh_state()
    # Use the test server as the physical gateway, including its host-route exception.
    command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0"])
    command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0", "table", "10003"])
    command(["ip", "rule", "add", "pref", "10003", "from", "10.77.254.2", "lookup", "10003"])
    pathlib.Path("/run/svpn").mkdir(parents=True, exist_ok=True)
    pathlib.Path("/run/svpn/local-exit.10_77_254_2.route").write_text(
        "owner=999999\nlocal_table=10003\nlocal_peer=10.77.254.2\n"
    )
    command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0", "table", "10004"])
    command(["ip", "rule", "add", "pref", "10004", "from", "10.77.253.2", "lookup", "10004"])
    pathlib.Path("/run/svpn/local-exit.10_77_253_2.route").write_text(
        "owner=999999\nlocal_table=10004\nlocal_peer=10.77.253.2\n"
    )
    command(["nft", "add", "table", "inet", "svpn_local_exit_10_77_253_2"])
    args = country_args(local_exit=True)
    with session(
        "local-exit",
        args=args,
        server_hosts=HOSTS,
        client_route=False,
        server_route=False,
        ready_timeout=20,
    ) as (process, path):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
        until(lambda: "local-exit: ready" in path.read_text(), seconds=15)
        assert "10004" not in command(["ip", "-4", "rule", "show"]).stdout
        assert not command(["ip", "-4", "route", "show", "table", "10004"]).stdout.strip()
        assert not pathlib.Path("/run/svpn/local-exit.10_77_253_2.route").exists()
        assert "svpn_local_exit_10_77_253_2" not in command(["nft", "list", "tables"]).stdout
        routes = command(["ip", "-4", "route", "show"]).stdout
        policy = command(["ip", "-4", "rule", "show"]).stdout
        assert "from 10.77.0.2" in policy, policy
        assert "lookup 10002" in policy, policy
        assert "0.0.0.0/1 dev svpn0" in routes, routes
        assert "128.0.0.0/1 dev svpn0" in routes, routes
        baseline = opened(path)
        source = target_tcp_echo(2, LOCAL_TARGET)
        assert source == "172.30.77.3", source
        udp_echo(LOCAL_TARGET)
        command(["ping", "-n", "-c", "1", "-W", "2", LOCAL_TARGET])
        by_source = target_tcp_echo(4, BY_TARGET)
        assert by_source == "172.30.77.3", by_source
        off_source = target_tcp_echo(5, OFF_TARGET)
        assert off_source == "172.30.77.3", off_source
        tcp_echo(3, peer=PEER)
        until(lambda: local_opened(path) == (5, 0, 0), seconds=20)
        until(lambda: delta(path, baseline) == {SERVER: 0, SERVER2: 1}, seconds=20)
        local_tuns = {
            item["ifname"]
            for item in json.loads(command(["ip", "-j", "link", "show"]).stdout)
            if item["ifname"] in {"svpn0", "tun0"}
        }
        assert local_tuns == {"svpn0", "tun0"}, local_tuns
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=5)
        until(
            lambda: not local_tuns
            & {item["ifname"] for item in json.loads(command(["ip", "-j", "link", "show"]).stdout)},
            seconds=10,
        )
        # SIGKILL skips down hooks; the next start reclaims the policy state.
        assert "svpn_local_exit" in command(["nft", "list", "tables"]).stdout
        ping_local(TARGET)
    cleanup_verified(process, server_hosts=HOSTS)

    restart_args = list(args)
    with session(
        "local-restart",
        args=restart_args,
        server_hosts=HOSTS,
        client_route=False,
        server_route=False,
        ready_timeout=20,
    ) as (process, path):
        until(lambda: "local-exit: ready" in path.read_text(), seconds=15)
        until(lambda: local_opened(path) is not None, seconds=10)
        baseline = local_opened(path)
        ping_local(LOCAL_TARGET)
        until(lambda: local_opened(path)[0] == baseline[0] + 1, seconds=20)
    cleanup_verified(process, server_hosts=HOSTS)
    assert "svpn_local_exit" not in command(["nft", "list", "tables"]).stdout
    assert "10003" not in command(["ip", "-4", "rule", "show"]).stdout
    assert not command(["ip", "-4", "route", "show", "table", "10003"]).stdout.strip()
    assert not pathlib.Path("/run/svpn/local-exit.10_77_254_2.route").exists()
    for host in HOSTS:
        assert "svpn_server_exit" not in command(ssh_to(host) + ["nft", "list", "tables"]).stdout
    print("PASS local-exit+VPN: supplied hooks, full-tunnel TCP/UDP/ICMP, restart and cleanup")


def test_hook_ownership_and_nondefault_pairs():
    peer = "10.77.253.2"
    peer_id = "10_77_253_2"
    local_env = [
        "env",
        "SVPN_HOOK_ROLE=local-exit",
        "SVPN_SESSION_ID=999991",
        f"SVPN_PEER_ADDR={peer}",
        "SVPN_TUN_ADDR=10.77.253.1",
        "SVPN_TUN_NAME=tun-test",
        f"SVPN_UPLINK_GATEWAY={SERVER}",
    ]
    local_up = local_env + ["/hooks/client-up", "eth0"]
    local_down = local_env + ["/hooks/client-down", "eth0"]
    foreign = "203.0.113.7"
    server_peers = ("10.77.0.2", "10.77.1.2")

    def remote(peer, event):
        env = [
            "env",
            "SVPN_HOOK_ROLE=server",
            "SVPN_SESSION_ID=999992",
            f"SVPN_PEER_ADDR={peer}",
            "SVPN_TUN_ADDR=10.77.0.1",
            "SVPN_TUN_NAME=svpn0",
        ]
        args = [f"/hooks/server-{event}"] + (["eth0"] if event == "up" else [])
        return command(ssh_to(SERVER) + env + args, check=False)

    try:
        command(local_up)
        table = command(["nft", "list", "table", "inet", f"svpn_local_exit_{peer_id}"]).stdout
        assert "ip saddr 10.77.253.2" in table
        assert "default via 172.30.77.2" in command(["ip", "route", "show", "table", "10004"]).stdout
        command(local_down)
        assert not command(["ip", "route", "show", "table", "10004"]).stdout.strip()
        assert "10004" not in command(["ip", "-4", "rule", "show"]).stdout

        default_peer = "10.77.254.2"
        default_env = [
            "env",
            "SVPN_HOOK_ROLE=local-exit",
            "SVPN_SESSION_ID=999994",
            f"SVPN_PEER_ADDR={default_peer}",
            "SVPN_TUN_ADDR=10.77.254.1",
            "SVPN_TUN_NAME=tun-test",
            f"SVPN_UPLINK_GATEWAY={SERVER}",
        ]
        pathlib.Path("/run/svpn/local-exit.10_77_254_2.route").unlink(missing_ok=True)
        command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0", "table", "10003"])
        command(["ip", "rule", "add", "pref", "10003", "from", default_peer, "lookup", "10003"])
        command(["nft", "add", "table", "inet", "svpn_local_exit_10_77_254_2"])
        foreign_up = default_env + ["/hooks/client-up", "eth0"]
        foreign_down = default_env + ["/hooks/client-down", "eth0"]
        assert command(foreign_up, check=False).returncode != 0
        assert command(foreign_down, check=False).returncode == 0
        assert command(["ip", "route", "show", "table", "10003"]).stdout.strip()
        assert "10003" in command(["ip", "-4", "rule", "show"]).stdout
        assert "svpn_local_exit_10_77_254_2" in command(["nft", "list", "tables"]).stdout
        command(["ip", "route", "flush", "table", "10003"])
        command(["ip", "rule", "del", "pref", "10003", "from", default_peer, "lookup", "10003"])
        command(["nft", "delete", "table", "inet", "svpn_local_exit_10_77_254_2"])

        pathlib.Path("/run/svpn/primary.route").unlink(missing_ok=True)
        command(["ip", "route", "replace", f"{foreign}/32", "via", SERVER, "dev", "eth0"])
        command(["ip", "route", "replace", "default", "via", SERVER, "dev", "eth0", "table", "10002"])
        primary_down = [
            "env",
            "SVPN_HOOK_ROLE=primary",
            "SVPN_SESSION_ID=999993",
            "SVPN_PEER_ADDR=10.77.0.1",
            "SVPN_TUN_ADDR=10.77.0.2",
            "SVPN_TUN_NAME=svpn0",
            "/hooks/client-down",
            "eth0",
            foreign,
        ]
        command(primary_down)
        assert command(["ip", "route", "show", f"{foreign}/32"]).stdout.strip()
        assert command(["ip", "route", "show", "table", "10002"]).stdout.strip()
        command(["ip", "route", "del", f"{foreign}/32"])
        command(["ip", "route", "flush", "table", "10002"])
        primary_up = primary_down.copy()
        primary_up[primary_up.index("/hooks/client-down")] = "/hooks/client-up"
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            command(["ip", "route", "replace", prefix, "via", SERVER, "dev", "eth0"])
            assert command(primary_up, check=False).returncode != 0
            assert command(primary_down, check=False).returncode == 0
            assert command(["ip", "route", "show", prefix]).stdout.strip()
            command(["ip", "route", "del", prefix])

        for remote_peer in server_peers:
            result = remote(remote_peer, "up")
            assert result.returncode == 0, result.stdout
            table = command(
                ssh_to(SERVER)
                + ["nft", "list", "table", "inet", f"svpn_server_exit_{remote_peer.replace('.', '_')}"]
            ).stdout
            assert f"ip saddr {remote_peer}" in table
        assert remote(server_peers[0], "down").returncode == 0
        remaining = command(ssh_to(SERVER) + ["nft", "list", "tables"]).stdout
        assert "svpn_server_exit_10_77_1_2" in remaining
        assert "svpn_server_exit_10_77_0_2" not in remaining
        assert remote(server_peers[1], "down").returncode == 0
    finally:
        command(local_down, check=False)
        command(["ip", "route", "del", f"{foreign}/32"], check=False)
        command(["ip", "route", "flush", "table", "10002"], check=False)
        command(["ip", "route", "flush", "table", "10003"], check=False)
        command(["ip", "rule", "del", "pref", "10003", "from", "10.77.254.2", "lookup", "10003"], check=False)
        command(["nft", "delete", "table", "inet", "svpn_local_exit_10_77_254_2"], check=False)
        for remote_peer in server_peers:
            remote(remote_peer, "down")
    print("PASS hook ownership: changed peer, non-default NAT, concurrent servers and foreign routes")


TESTS = [
    ("test_sticky_dst", test_sticky_dst),
    ("test_balance_diff", test_balance_diff),
    ("test_failover_move", test_failover_move),
    ("test_restart_restore", test_restart_restore),
    ("test_country_asn_scope", test_country_asn_scope),
    ("test_local_exits_hook_optional", test_local_exits_hook_optional),
    ("test_local_exits_and_vpn", test_local_exits_and_vpn),
    ("test_hook_ownership_and_nondefault_pairs", test_hook_ownership_and_nondefault_pairs),
]
