"""Lifecycle-pool group: up/down hooks on real Linux TUNs, pool failover, control loss, Checking."""

import concurrent.futures
import contextlib
import os
import pathlib
import re
import signal
import socket
import subprocess
import tempfile
import time
from shlex import quote

from _lib import (
    CLIENT,
    CLIENT_POOL,
    LOCAL,
    LOG_DIR,
    PEER,
    SERVER,
    SERVER2,
    SSH,
    cleanup_verified,
    command,
    session,
    ssh,
    ssh_to,
    tcp_echo,
    until,
)


def record(directory, body=""):
    return (
        'set -eu; test -d /sys/class/net/"$SVPN_TUN_NAME"; '
        'printf "%s|%s|%s|%s\\n" "$SVPN_EVENT" "$SVPN_TUN_NAME" '
        '"$SVPN_TUN_ADDR" "$SVPN_PEER_ADDR" >> ' + quote(str(directory / "events")) + "; " + body
    )


def verify_events(directory, events, name="svpn0"):
    rows = [line.split("|") for line in (directory / "events").read_text().splitlines()]
    assert [row[0] for row in rows] == events, rows
    assert all(row[2:] == [LOCAL, PEER] for row in rows), rows
    actual = rows[0][1]
    assert actual and all(row[1] == actual for row in rows), rows
    if name is not None:
        assert actual == name, rows
    return actual


@contextlib.contextmanager
def client(name, flags):
    # Unlike session(), failure cases may finish before an observer sees the TUN.
    path = LOG_DIR / ("hooks-" + name + ".log")
    with path.open("w") as log:
        process = subprocess.Popen(
            CLIENT + ["--log-level", "debug"] + flags, stdout=subprocess.PIPE, stderr=log
        )
        try:
            yield process, path
        except BaseException:
            print(path.read_text(), flush=True)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    raise AssertionError("hook cleanup exceeded service stop-grace") from None
            process.stdout.close()


def test_scripts():
    with tempfile.TemporaryDirectory(prefix="svpn hook ") as temporary:
        directory = pathlib.Path(temporary)
        up = directory / "up script"
        down = directory / "down script"
        up.write_text(
            "#!/bin/sh\n"
            + record(
                directory,
                "printf HOOK-STDOUT; printf HOOK-STDERR >&2; touch " + quote(str(directory / "up.done")),
            )
            + "\n"
        )
        down.write_text("#!/bin/sh\n" + record(directory, "true") + "\n")
        up.chmod(0o700)
        down.chmod(0o700)
        flags = ["--up-script", os.path.relpath(up), "--down-script", str(down)]
        args = CLIENT.copy()
        args[args.index("--tun-name") + 1] = ""
        path = LOG_DIR / "hooks-scripts.log"
        with path.open("w") as log:
            process = subprocess.Popen(args + flags, stdout=subprocess.PIPE, stderr=log)
            try:
                until(lambda: (directory / "up.done").exists())
                process.terminate()
                stdout, _ = process.communicate(timeout=15)
                assert process.returncode == 0, path.read_text()
                assert stdout == b"", stdout
                output = path.read_text()
                assert "HOOK-STDOUT" in output and "HOOK-STDERR" in output, output
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=25)
        name = verify_events(directory, ["up", "down"], name=None)
        cleanup_verified(process, tun_name=name)
    print("PASS hooks scripts: relative path/spaces, kernel TUN name, env, stdout separation")


def test_up_barrier_and_routes():
    with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
        directory = pathlib.Path(temporary)
        extra_route = "192.0.2.123/32"
        up = record(
            directory,
            'ip route replace "$SVPN_PEER_ADDR/32" dev "$SVPN_TUN_NAME" src "$SVPN_TUN_ADDR"; '
            "ip route replace " + extra_route + ' dev "$SVPN_TUN_NAME"; '
            "touch " + quote(str(directory / "up.begin")) + "; sleep 7; "
            "touch " + quote(str(directory / "up.done")),
        )
        down = record(
            directory,
            "ip route del " + extra_route + ' dev "$SVPN_TUN_NAME"; '
            'ip route del "$SVPN_PEER_ADDR/32" dev "$SVPN_TUN_NAME"',
        )
        args = CLIENT + ["--mimic", "mosh", "--up-command", up, "--down-command", down]
        with session("hooks-barrier", args=args, client_route=False, ready_by_tun=True) as (process, path):
            until(lambda: (directory / "up.begin").exists())
            assert extra_route.split("/")[0] in command(["ip", "route", "show", extra_route]).stdout
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.4)
                sock.sendto(b"before-up", (PEER, 9000))
                try:
                    sock.recv(128)
                    raise AssertionError("TUN served traffic before up completed")
                except socket.timeout:
                    pass
                assert "vpn: started" not in path.read_text()
                until(lambda: (directory / "up.done").exists(), seconds=9)
                until(lambda: "vpn: started" in path.read_text())
                assert path.read_text().count("heartbeat received") >= 2, path.read_text()
                assert process.poll() is None, path.read_text()
                sock.settimeout(5)
                assert sock.recv(128) == b"before-up"
            tcp_echo(31)
        assert process.returncode == 0, path.read_text()
        verify_events(directory, ["up", "down"])
        assert not command(["ip", "route", "show", extra_route]).stdout.strip()
        cleanup_verified(process)
    print("PASS hooks barrier: no early data, live heartbeats, hook-owned routes and TCP/UDP")


def test_up_failures():
    for name in ["exit", "signal", "spawn", "timeout"]:
        with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
            directory = pathlib.Path(temporary)
            body = {
                "exit": "exit 7",
                "signal": "kill -TERM $$",
                "timeout": "sleep 60 & echo $! > " + quote(str(directory / "child.pid")) + "; wait",
            }
            if name == "spawn":
                script = directory / "bad interpreter"
                script.write_text("#!/no/such/hook/interpreter\n")
                script.chmod(0o700)
                flags = ["--up-script", str(script)]
            else:
                flags = ["--up-command", record(directory, body[name])]
            flags += ["--down-command", record(directory, "true")]
            with client("up-" + name, flags) as (process, path):
                process.wait(timeout=25)
                assert process.returncode != 0, path.read_text()
                assert "vpn: started" not in path.read_text(), path.read_text()
                assert "hook up:" in path.read_text(), path.read_text()
                verify_events(directory, ["down"] if name == "spawn" else ["up", "down"])
                if name == "timeout":
                    pid = (directory / "child.pid").read_text().strip()
                    until(lambda pid=pid: not pathlib.Path("/proc/" + pid).exists())
            cleanup_verified(process)
    print("PASS hooks failed up: exit/signal/spawn/timeout, compensation down, descendants reaped")


def test_signals_during_up():
    for stop in [signal.SIGINT, signal.SIGTERM]:
        with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
            directory = pathlib.Path(temporary)
            up = record(directory, "sleep 60 & echo $! > " + quote(str(directory / "child.pid")) + "; wait")
            down = record(directory, "sleep 0.3; touch " + quote(str(directory / "down.done")))
            with client("signal-" + str(stop), ["--up-command", up, "--down-command", down]) as (
                process,
                path,
            ):
                until(lambda directory=directory: (directory / "child.pid").exists())
                process.send_signal(stop)
                until(lambda directory=directory: (directory / "events").read_text().count("down|") == 1)
                assert pathlib.Path("/sys/class/net/svpn0").exists()
                process.send_signal(stop)
                process.wait(timeout=15)
                assert process.returncode == 0, path.read_text()
                assert (directory / "down.done").exists()
                assert "vpn: started" not in path.read_text(), path.read_text()
                verify_events(directory, ["up", "down"])
                pid = (directory / "child.pid").read_text().strip()
                until(lambda pid=pid: not pathlib.Path("/proc/" + pid).exists())
            cleanup_verified(process)
    print("PASS hooks signals: cancel/reap up, TUN alive during down, repeat signals keep cleanup")


def test_failed_down_and_partial_up():
    with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
        directory = pathlib.Path(temporary)
        route = "192.0.2.124/32"
        up = record(directory, "ip route replace " + route + ' dev "$SVPN_TUN_NAME"; exit 7')
        down = record(directory, "ip route del " + route + ' dev "$SVPN_TUN_NAME"; exit 9')
        with client("partial-up", ["--up-command", up, "--down-command", down]) as (process, path):
            process.wait(timeout=20)
            output = path.read_text()
            assert process.returncode != 0, output
            assert "cleanup failed" in output and "hook down:" in output, output
            assert "hook up:" in output.splitlines()[-1], output
            verify_events(directory, ["up", "down"])
            assert not command(["ip", "route", "show", route]).stdout.strip()
        cleanup_verified(process)

    for name in ["signal", "spawn", "timeout"]:
        with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
            directory = pathlib.Path(temporary)
            if name == "spawn":
                script = directory / "bad interpreter"
                script.write_text("#!/no/such/hook/interpreter\n")
                script.chmod(0o700)
                flags = ["--down-script", str(script)]
            else:
                body = (
                    "kill -TERM $$"
                    if name == "signal"
                    else "sleep 60 & echo $! > " + quote(str(directory / "child.pid")) + "; wait"
                )
                flags = ["--down-command", record(directory, body)]
            # Down also works without a configured up hook.
            with client("down-" + name, flags) as (process, path):
                until(lambda: "vpn: started" in path.read_text())
                process.terminate()
                if name == "timeout":
                    until(lambda directory=directory: (directory / "child.pid").exists())
                    assert pathlib.Path("/sys/class/net/svpn0").exists()
                process.wait(timeout=15)
                assert process.returncode != 0 and "hook down:" in path.read_text(), path.read_text()
                if name == "spawn":
                    assert not (directory / "events").exists()
                    assert "spawn failed" in path.read_text(), path.read_text()
                else:
                    verify_events(directory, ["down"])
                if name == "timeout":
                    assert "timed out" in path.read_text(), path.read_text()
                    pid = (directory / "child.pid").read_text().strip()
                    until(lambda pid=pid: not pathlib.Path("/proc/" + pid).exists())
            cleanup_verified(process)
    print(
        "PASS hooks cleanup: partial up rollback, original error retained, "
        "down-only signal/spawn/timeout drops TUN"
    )


def test_fatal_during_up():
    with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
        directory = pathlib.Path(temporary)
        up = record(directory, "sleep 60 & echo $! > " + quote(str(directory / "child.pid")) + "; wait")
        with client("fatal", ["--up-command", up, "--down-command", record(directory, "true")]) as (
            process,
            path,
        ):
            until(lambda: (directory / "child.pid").exists())
            ssh("pkill -x svpn")
            # Exit must come from handling the SSH loss itself, not the 10 s hook deadline.
            process.wait(timeout=9)
            assert process.returncode != 0, path.read_text()
            assert "hook up: timed out" not in path.read_text(), path.read_text()
            assert "vpn: started" not in path.read_text(), path.read_text()
            verify_events(directory, ["up", "down"])
            pid = (directory / "child.pid").read_text().strip()
            until(lambda: not pathlib.Path("/proc/" + pid).exists())
        cleanup_verified(process)
    print("PASS hooks fatal: SSH loss cancels up and runs down before TUN cleanup")


def test_blocked_hook_output():
    with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
        directory = pathlib.Path(temporary)
        up = record(
            directory, "yes HOOK-OUTPUT & echo $! > " + quote(str(directory / "child.pid")) + "; wait"
        )
        args = CLIENT + ["--up-command", up, "--down-command", record(directory, "true")]
        with session("hooks-blocked-output", args=args, blocked_logs=True) as (process, _path):
            process.wait(timeout=15)
            assert process.returncode != 0
            verify_events(directory, ["up", "down"])
            pid = (directory / "child.pid").read_text().strip()
            until(lambda: not pathlib.Path("/proc/" + pid).exists())
        cleanup_verified(process)
    print("PASS hooks blocked stderr: output backpressure cannot prevent timeout and cleanup")


def test_pool_transitions():
    with tempfile.TemporaryDirectory(prefix="svpn-hooks-") as temporary:
        directory = pathlib.Path(temporary)
        args = CLIENT_POOL + [
            "--mimic",
            "mosh",
            "--up-command",
            record(directory, "sleep 1"),
            "--down-command",
            record(directory, "true"),
        ]
        with session("hooks-pool", args=args, server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
            process,
            path,
        ):
            until(lambda: "serving (2/2 servers ready," in path.read_text())
            verify_events(directory, ["up"])
            before = command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip()
            command(ssh_to(SERVER2) + ["iptables -w -I INPUT -p udp -j DROP"])
            try:
                until(lambda: f"ssh[{SERVER2}]: checking round failed" in path.read_text(), seconds=20)
                tcp_echo(32)
                verify_events(directory, ["up"])
            finally:
                command(ssh_to(SERVER2) + ["iptables -w -D INPUT -p udp -j DROP"])
            until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 2, seconds=30)
            assert command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip() == before
            command(ssh_to(SERVER2) + ["pkill -x svpn"])
            until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 3, seconds=30)
            assert command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip() != before
            assert process.poll() is None, path.read_text()
            tcp_echo(33)
            verify_events(directory, ["up"])
        verify_events(directory, ["up", "down"])
        cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS hooks pool: one TUN up/down across second Ready, Checking, recovery and SSH retry")


def run():
    test_scripts()
    test_up_barrier_and_routes()
    test_up_failures()
    test_signals_during_up()
    test_failed_down_and_partial_up()
    test_fatal_during_up()
    test_blocked_hook_output()
    test_pool_transitions()


def kill_server_process():
    # Built-in SSH leaves no separate child process: losing control kills the server binary,
    # the client sees the channel Close and must stop.
    ssh("pkill -x svpn")


def drop_ssh_traffic():
    # Channel death without EOF: SSH packets vanish silently; only heartbeat can save it.
    command(["iptables", "-w", "-A", "OUTPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"])


def restore_ssh_traffic():
    # Remove all copies: a run after a crash may have added a second instance.
    while (
        command(
            ["iptables", "-w", "-D", "OUTPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=False
        ).returncode
        == 0
    ):
        pass


def pool_args():
    # Weights 2:1 — smooth WRR: flows 1,2→SERVER, 3→SERVER2, deterministically.
    args = [CLIENT[0], "multi"] + CLIENT[1:]
    args[args.index("--server") + 1] = f"{SERVER},weight=2"
    return args + ["--server", SERVER2]


def test_hostname_servers():
    hosts = pathlib.Path("/etc/hosts")
    original = hosts.read_text()
    name, ipv6_only = "svpn-reconnect.test", "svpn-ipv6.test"
    loopback = "svpn-loopback.test"
    secondary = "172.30.77.6"
    drop = ["iptables", "-w", "-A", "OUTPUT", "-d", SERVER, "-p", "tcp", "--dport", "41026", "-j", "DROP"]
    undrop = drop[:2] + ["-D"] + drop[3:]
    known = pathlib.Path("/tmp/hostname-known-hosts")
    known.unlink(missing_ok=True)
    env = dict(os.environ, SVPN_KNOWN_HOSTS=str(known))
    ssh(f"ip addr add {secondary}/24 dev eth0")
    try:
        records = original + f"\n::1 {ipv6_only}\n127.0.0.1 {loopback}\n"
        hosts.write_text(records + f"{SERVER} {name}\n")
        args = CLIENT.copy()
        for host, reason in [(ipv6_only, "no IPv4 addresses"), (loopback, "not a unicast IPv4 address")]:
            args[args.index("--server") + 1] = host
            result = command(args, check=False, timeout=20)
            assert result.returncode != 0 and reason in result.stdout, result.stdout
            assert "connecting to" not in result.stdout, result.stdout
            assert not pathlib.Path("/sys/class/net/svpn0").exists()
            print(f"PASS hostname: {reason} fails before SSH/TUN")

        args[args.index("--server") + 1] = name
        result = command(
            args + ["--ssh-host-key", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            check=False,
            timeout=20,
        )
        assert result.returncode != 0 and "host key rejected" in result.stdout, result.stdout
        assert not pathlib.Path("/sys/class/net/svpn0").exists()
        print("PASS hostname: host-key pin mismatch is still rejected")

        for mode, flags in [("auto", []), ("tcp", ["--mimic", "ssh", "--tcp-port", "41026"])]:
            hosts.write_text(records + f"{SERVER} {name}\n")
            args = pool_args() + flags
            args[args.index("--server") + 1] = f"{name.upper()},weight=2"
            with session(
                f"hostname-reconnect-{mode}",
                args=args,
                env=env,
                server_hosts=[SERVER, SERVER2],
                ready_timeout=30,
            ) as (process, path):
                until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=15)
                assert f"resolved {name} to {SERVER}" in path.read_text()
                tcp_echo(7)
                hosts.write_text(records + f"{secondary} {name}\n")
                if mode == "tcp":
                    # SSH stays reachable; stale data connections must not work.
                    command(drop)
                kill_server_process()
                until(lambda: f"resolved {name} to {secondary}" in path.read_text(), seconds=30)
                until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 2, seconds=30)
                ssh(f"ip route replace {LOCAL}/32 dev svpn0 src {PEER}")
                for index in range(3):
                    tcp_echo(index)
                assert process.poll() is None, path.read_text()
            cleanup_verified(process, server_hosts=[SERVER, SERVER2])
            entries = known.read_text().splitlines()
            assert any(line.startswith(f"{name}:22 ") for line in entries), entries
            assert not any(line.startswith(f"{secondary}:22 ") for line in entries), entries
            print(f"PASS hostname {mode}: reconnect uses new IP for SSH/data; TOFU keeps the name")
    finally:
        while command(undrop, check=False).returncode == 0:
            pass
        hosts.write_text(original)
        ssh(f"ip addr del {secondary}/24 dev eth0")


def test_pool_two_servers():
    with session("pool-two", args=pool_args(), server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(tcp_echo, range(30)))
        log = path.read_text()
        assert f"[server {SERVER}]" in log and f"[server {SERVER2}]" in log, (
            "both servers must relay stderr with a host tag"
        )
        first = len(re.findall(rf"\[server {SERVER}\].*flow_open role=server", log))
        second = len(re.findall(rf"\[server {SERVER2}\].*flow_open role=server", log))
        assert (first, second) == (20, 10), (first, second)
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS pool distribution: 2:1 weights split 30 flows exactly 20/10")


def test_pool_udp_ports():
    # Per-server udp-ports= must reach the remote serve command line (each
    # host gets its own non-overlapping range) and carry traffic.
    args = [
        "svpn",
        "multi",
        "--server",
        f"{SERVER},user=root,identity=/keys/client,udp-ports=61000-61009",
        "--server",
        f"{SERVER2},user=root,identity=/keys/client,udp-ports=62000-62009",
        "--peer-tun-name",
        "svpn0",
        "--tun-name",
        "svpn0",
    ]
    with session("pool-ports", args=args, server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=10)
        tcp_echo(0)
        for host, low in ((SERVER, "61000"), (SERVER2, "62000")):
            until(
                lambda host=host, low=low: low
                in command(ssh_to(host) + ['pgrep -af "svpn serve"'], check=False).stdout
            )
        log = path.read_text()
        assert f"[server {SERVER}]" in log and f"[server {SERVER2}]" in log
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS pool udp ports: per-server ranges reach both serve processes")


def test_pool_failover():
    with session("pool-failover", args=pool_args(), server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 1, seconds=10)

        def flows_on(server):
            # Tagged relayed server logs: `[server X] flow_active role=server id=N`.
            return len(
                re.findall(rf"\[server {re.escape(server)}\].*flow_active role=server", path.read_text())
            )

        # Which stream rides which server is WRR+SYN-retry nondeterministic:
        # keep connecting until BOTH servers visibly own at least one flow.
        streams = []
        try:
            while flows_on(SERVER2) == 0 or flows_on(SERVER) == 0:
                stream = socket.create_connection((PEER, 9000), timeout=15)
                streams.append(stream)
                stream.sendall(b"x")
                stream.settimeout(10)
                assert stream.recv(1) == b"x", "echo must arrive"
                assert len(streams) < 12, "never placed a flow on SERVER2"
            victims_expected = flows_on(SERVER2)
            # Killing the remote binary closes the SSH channel: fast, deterministic loss.
            # Count-based waits: a bare substring would match the stale bootstrap-phase
            # serving/link lines that precede the steady 2/2 state.
            command(ssh_to(SERVER2) + ["pkill", "-x", "svpn"])
            until(lambda: path.read_text().count("serving (1/2 servers ready,") >= 2, seconds=15)
            until(lambda: "link failed" in path.read_text(), seconds=5)
            # Retired flows reset fast instead of hanging on retransmits;
            # survivors keep echoing fresh bytes.
            victims = survivors = 0
            for stream in streams:
                stream.settimeout(10)
                try:
                    stream.sendall(b"y")
                    assert stream.recv(1) == b"y", "surviving flow must still echo"
                    survivors += 1
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    victims += 1
                stream.close()
            assert victims == victims_expected, (victims, victims_expected)
            assert survivors >= 1
            tcp_echo(2)  # new flows go to the surviving server
            # The supervisor restarts the server binary over SSH and rejoins the pool.
            until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 2, seconds=45)
            tcp_echo(3)
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS pool failover: RST for retired flows, survivor serves, link rejoins")


def test_pool_backoff():
    drop = ["iptables", "-w", "-A", "OUTPUT", "-d", SERVER2, "-p", "tcp", "--dport", "22", "-j", "DROP"]
    undrop = drop[:2] + ["-D"] + drop[3:]
    # D6: one unreachable server must not block bootstrap of the other.
    # The drop goes up only after session() finished its operator routes:
    # session setup itself reaches both servers over SSH.
    with session("pool-backoff", args=pool_args(), server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        command(drop)
        try:
            tcp_echo(0)
            until(lambda: f"ssh[{SERVER2}]: retrying in 1 s" in path.read_text(), seconds=15)
            until(lambda: f"ssh[{SERVER2}]: retrying in 2 s" in path.read_text(), seconds=20)
            command(undrop)
            until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 1, seconds=30)
            tcp_echo(1)
        finally:
            while command(undrop, check=False).returncode == 0:
                pass
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS pool backoff: unreachable link retries with growing delay, joins later")


def test_pool_all_down():
    drops = [
        ["iptables", "-w", "-A", "OUTPUT", "-d", host, "-p", "tcp", "--dport", "22", "-j", "DROP"]
        for host in (SERVER, SERVER2)
    ]
    undrops = [drop[:2] + ["-D"] + drop[3:] for drop in drops]
    for drop in drops:
        command(drop)
    # No session() here: it waits for `vpn: started`, which never happens
    # when every link is down. The VPN must exit on its own, non-zero.
    path = LOG_DIR / "pool-all-down.log"
    try:
        with path.open("w") as log:
            process = subprocess.Popen(
                pool_args() + ["--log-level", "debug"], stdout=subprocess.DEVNULL, stderr=log
            )
            process.wait(timeout=60)
        assert process.returncode != 0, path.read_text()
        assert "no server available" in path.read_text(), path.read_text()
        assert not pathlib.Path("/sys/class/net/svpn0").exists(), "client TUN survived"
    finally:
        for undrop in undrops:
            while command(undrop, check=False).returncode == 0:
                pass
        if process.poll() is None:
            process.kill()
    print("PASS pool all-down: every link lost stops the VPN with a non-zero code")


def test_ssh_loss():
    with session("ssh-loss") as (process, path):
        command(["ping", "-n", "-c", "1", "-W", "2", PEER])
        kill_server_process()
        process.wait(timeout=8)
        assert process.returncode != 0, path.read_text()
    cleanup_verified(process)
    print("PASS control loss: session stops without reconnect")


def test_heartbeat_loss():
    with session("heartbeat-loss") as (process, path):
        command(["ping", "-n", "-c", "1", "-W", "2", PEER])
        traffic = subprocess.Popen(
            ["ping", "-n", "-q", "-i", "0.001", PEER],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            until(lambda: path.read_text().count("flow_active role=client") >= 2)
            drop_ssh_traffic()
            try:
                process.wait(timeout=8)
            finally:
                restore_ssh_traffic()
            assert process.returncode != 0
            assert "heartbeat timeout" in path.read_text(), path.read_text()
        finally:
            traffic.send_signal(signal.SIGINT)
            output, _ = traffic.communicate(timeout=3)
        counts = re.search(r"(\d+) packets transmitted, (\d+) received", output)
        assert counts and int(counts[1]) > 100 and int(counts[2]) > 10, output
    cleanup_verified(process)
    print("PASS heartbeat loss with SSH open and continuous traffic: both sides stop")


def test_blocked_stderr():
    for failure in (kill_server_process, drop_ssh_traffic):
        with session("blocked-stderr", blocked_logs=True) as (process, _path):
            command(["ping", "-n", "-c", "1", "-W", "2", PEER])
            failure()
            try:
                process.wait(timeout=8)
            finally:
                if failure is drop_ssh_traffic:
                    restore_ssh_traffic()
            assert process.returncode != 0
        cleanup_verified(process)
    print("PASS full stderr: control loss and heartbeat loss still remove both TUNs")


def test_server_blocked_stderr():
    ssh("python3 /e2e/blocked_stderr.py", timeout=20)
    assert command(SSH + ["pgrep -x svpn"], check=False).returncode == 1
    print("PASS server stderr full: live stdin, heartbeat timeout exits and removes TUN")


def test_sigkill_takeover():
    # ISSUE-stale-serve: a SIGKILLed client leaves the server serve holding
    # TUN/UDP only until its heartbeat window; the next client must take over
    # without manual cleanup (the serve TUN-busy retry absorbs the window).
    with session("sigkill-takeover") as (process, _path):
        command(["ping", "-n", "-c", "1", "-W", "2", PEER])
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=3)
    started = time.monotonic()
    until(lambda: command(ssh_to(SERVER) + ["pgrep -x svpn"], check=False).returncode == 1, seconds=10)
    elapsed = time.monotonic() - started
    assert elapsed <= 6, f"stale serve lived {elapsed:.1f}s"
    with session("sigkill-takeover-2", ready_timeout=15) as (second, _second_path):
        command(["ping", "-n", "-c", "1", "-W", "2", PEER])
    cleanup_verified(second)
    print(f"PASS sigkill takeover: stale serve gone in {elapsed:.1f}s, reconnect works")


def test_checking_recovers_without_ssh_restart():
    args = pool_args() + ["--mimic", "mosh"]
    with session("checking-recovery", args=args, server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=10)
        before = command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip()
        command(ssh_to(SERVER2) + ["iptables -w -I INPUT -p udp -j DROP"])
        try:
            until(lambda: f"ssh[{SERVER2}]: data path lost, control alive" in path.read_text(), seconds=15)
            assert process.poll() is None, path.read_text()
            tcp_echo(23)  # The healthy server still accepts new flows.
            until(lambda: f"ssh[{SERVER2}]: checking round failed" in path.read_text(), seconds=15)
            assert command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip() == before
        finally:
            command(ssh_to(SERVER2) + ["iptables -w -D INPUT -p udp -j DROP"])
        until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 2, seconds=30)
        assert command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip() == before
        tcp_echo(24)
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS Checking: live SSH, failed round, healthy peer serves, same server process rejoins")


def test_checking_preserves_active_tcp_flows():
    args = pool_args() + ["--mimic", "ssh", "--tcp-port", "41033"]
    rule = "INPUT -i svpn0 -p icmp --icmp-type echo-request -j DROP"
    with session("checking-active-tcp", args=args, server_hosts=[SERVER, SERVER2], ready_timeout=20) as (
        process,
        path,
    ):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=10)
        before = command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip()
        streams = []
        try:
            for _ in range(6):
                stream = socket.create_connection((PEER, 9000), timeout=15)
                streams.append(stream)
                stream.settimeout(2)
                stream.sendall(b"x")
                assert stream.recv(1) == b"x"
            # Two independent TCP data sockets on SERVER2; abort only one.
            sockets = command(
                ["ss", "-Htn", "state", "established", "dst", SERVER2, "dport", "=", ":41033"]
            ).stdout.splitlines()
            assert len(sockets) == 2, sockets
            local_port = int(sockets[0].split()[-2].rsplit(":", 1)[1])
            victims = set()

            def exchange():
                for index, stream in enumerate(streams):
                    if index in victims:
                        continue
                    try:
                        stream.sendall(b"y")
                        if stream.recv(1) != b"y":
                            victims.add(index)
                    except OSError:
                        victims.add(index)
                assert len(victims) <= 1, "Checking broke another committed flow"
                assert process.poll() is None, path.read_text()

            command(ssh_to(SERVER2) + ["iptables -w -I " + rule])
            try:
                # Delay FlowClose so the local transport error wins the queue race.
                control_drop = ["INPUT", "-s", SERVER2, "-p", "tcp", "--sport", "22", "-j", "DROP"]
                reset = [
                    "OUTPUT",
                    "-d",
                    SERVER2,
                    "-p",
                    "tcp",
                    "--dport",
                    "41033",
                    "--sport",
                    str(local_port),
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ]
                command(["iptables", "-w", "-I"] + control_drop)
                try:
                    command(["iptables", "-w", "-I"] + reset)
                    try:
                        exchange()
                        until(
                            lambda: f"ssh[{SERVER2}]: data path lost, control alive" in path.read_text(),
                            seconds=3,
                        )
                    finally:
                        command(["iptables", "-w", "-D"] + reset)
                finally:
                    command(["iptables", "-w", "-D"] + control_drop)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    exchange()
                    time.sleep(0.2)
                assert len(victims) == 1, "aborted data socket did not retire its flow"
                assert f"ssh[{SERVER2}]: checking round failed" in path.read_text(), path.read_text()
                assert command(ssh_to(SERVER2) + ["pgrep -x svpn"]).stdout.strip() == before
                tcp_echo(25)  # New assignments still use the healthy neighbour.
            finally:
                command(ssh_to(SERVER2) + ["iptables -w -D " + rule])
            until(lambda: path.read_text().count("serving (2/2 servers ready,") >= 2, seconds=30)
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print("PASS Checking: one TCP reset, other committed flows survive failed kernel round")


# ── automatic TUN name and address assignment (#181) ──

POOL_ADDR = re.compile(r"^10\.77\.(\d{1,3})\.([12])$")


def auto_args(extra=None):
    # No --tun-name/--peer-tun-name/--tun-addr/--peer-addr: automatic mode.
    return [
        "svpn",
        "--server",
        SERVER,
        "--ssh-user",
        "root",
        "--ssh-identity",
        "/keys/client",
        "--log-level",
        "debug",
    ] + (extra or [])


def check_pool_pair(local, peer):
    match = POOL_ADDR.match(peer)
    assert match and match.group(2) == "1", (local, peer)
    assert local == "10.77." + match.group(1) + ".2", (local, peer)


@contextlib.contextmanager
def auto_client(name, args, hosts):
    """Automatic-mode client: the TUN name and addresses come from hook events."""
    with tempfile.TemporaryDirectory(prefix="svpn-auto-") as temporary:
        directory = pathlib.Path(temporary)
        path = LOG_DIR / (name + ".log")
        with path.open("w") as log:
            process = subprocess.Popen(
                args + ["--up-command", record(directory), "--down-command", record(directory)],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
            tun = local = peer = None
            try:
                until(lambda: (directory / "events").exists() and (directory / "events").read_text())
                row = [line.split("|") for line in (directory / "events").read_text().splitlines()][0]
                assert row[0] == "up", row
                tun, local, peer = row[1], row[2], row[3]
                until(lambda: "vpn: started" in path.read_text())
                assert process.poll() is None, path.read_text()
                command(["ip", "route", "replace", peer + "/32", "dev", tun, "src", local])
                for host in hosts:
                    command(
                        ssh_to(host)
                        + [
                            "dev=$(ip -o -4 addr show | awk '$4 == \"" + peer + "\" {print $2}'); "
                            'test -n "$dev" && ip route replace ' + local + '/32 dev "$dev" src ' + peer
                        ]
                    )
                yield process, path, (tun, local, peer), directory
            except BaseException:
                print(path.read_text(), flush=True)
                raise
            finally:
                if peer is not None:
                    subprocess.run(
                        ["ip", "route", "del", peer + "/32", "dev", tun],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=25)


def assert_fully_stopped(process, directory, hosts):
    assert process.returncode == 0, process.returncode
    rows = [line.split("|") for line in (directory / "events").read_text().splitlines()]
    assert [row[0] for row in rows] == ["up", "down"], rows
    assert rows[0][1:] == rows[1][1:], "up/down must see the same TUN name and addresses"

    def clean():
        if command(["ip", "-o", "link", "show", "type", "tun"], check=False).stdout.strip():
            return False
        for host in hosts:
            if command(ssh_to(host) + ["ip -o link show type tun"], check=False).stdout.strip():
                return False
            if command(ssh_to(host) + ["pgrep -x svpn"], check=False).returncode != 1:
                return False
        return True

    until(clean)


def test_auto_assignment_and_restart():
    pair = None
    for _ in range(2):
        with auto_client("auto-single", auto_args(), [SERVER]) as (
            process,
            path,
            (tun, local, peer),
            directory,
        ):
            check_pool_pair(local, peer)
            tcp_echo(0, peer=peer)
            server_view = ssh("ip -o -4 addr show | awk '$4 == \"" + peer + "\"'").stdout
            assert server_view.split()[5].startswith(local + "/"), server_view
            process.terminate()
            process.wait(timeout=25)
            assert_fully_stopped(process, directory, [SERVER])
        if pair is None:
            pair = (local, peer)
        else:
            assert (local, peer) == pair, "the freed pool pair must be reused"
    print("PASS auto single: kernel TUN names, pool pair, reused after restart")


def test_auto_two_clients_one_server():
    with (
        auto_client("auto-a", auto_args(), [SERVER]) as (_, _, (tun_a, local_a, peer_a), _),
        auto_client("auto-b", auto_args(), [SERVER]) as (_, _, (tun_b, local_b, peer_b), _),
    ):
        assert (local_a, peer_a) != (local_b, peer_b), "two clients must get distinct pairs"
        assert tun_a != tun_b
        check_pool_pair(local_a, peer_a)
        check_pool_pair(local_b, peer_b)
        tcp_echo(1, peer=peer_a)
        tcp_echo(2, peer=peer_b)
    print("PASS auto two clients: distinct pairs and TUN names on one server")


def test_auto_explicit_pair_lock():
    flags = ["--tun-addr", "10.77.9.2", "--peer-addr", "10.77.9.1"]
    with auto_client("auto-explicit", auto_args(flags), [SERVER]) as (
        process,
        _,
        (_, local, peer),
        directory,
    ):
        assert (local, peer) == ("10.77.9.2", "10.77.9.1")
        tcp_echo(3, peer=peer)
        # Same explicit pair from a second client: lock-token collision, fast failure.
        log = LOG_DIR / "auto-explicit-busy.log"
        with log.open("w") as sink:
            busy = subprocess.Popen(auto_args(flags), stdout=subprocess.DEVNULL, stderr=sink)
            assert busy.wait(timeout=30) != 0
        assert "already used" in log.read_text(), log.read_text()
        # An explicit pair outside the pool subnet needs no lock and works.
        with auto_client(
            "auto-custom", auto_args(["--tun-addr", "192.168.55.2", "--peer-addr", "192.168.55.1"]), [SERVER]
        ) as (_, _, (_, custom_local, custom_peer), _):
            assert (custom_local, custom_peer) == ("192.168.55.2", "192.168.55.1")
            tcp_echo(4, peer=custom_peer)
    print("PASS auto explicit: honored pair, flock collision fails fast, custom subnet unlocked")


def test_auto_pool_shared_pair():
    args = [
        "svpn",
        "multi",
        "--server",
        f"{SERVER},user=root,identity=/keys/client",
        "--server",
        f"{SERVER2},user=root,identity=/keys/client",
        "--log-level",
        "debug",
    ]
    with auto_client("auto-pool", args, [SERVER, SERVER2]) as (process, path, (tun, local, peer), directory):
        until(lambda: "serving (2/2 servers ready," in path.read_text(), seconds=20)
        check_pool_pair(local, peer)
        for host in (SERVER, SERVER2):
            view = command(ssh_to(host) + ["ip -o -4 addr show | awk '$4 == \"" + peer + "\"'"]).stdout
            assert view.split()[5].startswith(local + "/"), (host, view)
        for index in range(4):
            tcp_echo(10 + index, peer=peer)
        process.terminate()
        process.wait(timeout=25)
        assert_fully_stopped(process, directory, [SERVER, SERVER2])
    print("PASS auto pool: both servers share one pair, traffic flows")


TESTS = [
    ("test_lifecycle_hooks", run),
    ("test_hostname_servers", test_hostname_servers),
    ("test_pool_two_servers", test_pool_two_servers),
    ("test_pool_udp_ports", test_pool_udp_ports),
    ("test_pool_failover", test_pool_failover),
    ("test_pool_backoff", test_pool_backoff),
    ("test_pool_all_down", test_pool_all_down),
    ("test_ssh_loss", test_ssh_loss),
    ("test_heartbeat_loss", test_heartbeat_loss),
    ("test_blocked_stderr", test_blocked_stderr),
    ("test_server_blocked_stderr", test_server_blocked_stderr),
    ("test_sigkill_takeover", test_sigkill_takeover),
    ("test_checking_recovers_without_ssh_restart", test_checking_recovers_without_ssh_restart),
    ("test_checking_preserves_active_tcp_flows", test_checking_preserves_active_tcp_flows),
    ("test_auto_assignment_and_restart", test_auto_assignment_and_restart),
    ("test_auto_two_clients_one_server", test_auto_two_clients_one_server),
    ("test_auto_explicit_pair_lock", test_auto_explicit_pair_lock),
    ("test_auto_pool_shared_pair", test_auto_pool_shared_pair),
    ("test_auto_assignment_and_restart", test_auto_assignment_and_restart),
    ("test_auto_two_clients_one_server", test_auto_two_clients_one_server),
    ("test_auto_explicit_pair_lock", test_auto_explicit_pair_lock),
    ("test_auto_pool_shared_pair", test_auto_pool_shared_pair),
]
