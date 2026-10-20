"""Bootstrap group: CLI/TOML parity, credentials, TUN naming, log levels, stats and readiness."""

import json
import os
import pathlib
import re
import shlex
import signal
import socket
import subprocess
import tempfile
import time

from _lib import (
    CLIENT,
    LOCAL,
    LOG_DIR,
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


def traffic(index):
    tcp_echo(index)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        payload = b"TOML UDP test"
        sock.sendto(payload, (PEER, 9000))
        received, address = sock.recvfrom(2048)
        assert received == payload and address == (PEER, 9000)
    command(["ping", "-n", "-c", "2", "-W", "2", PEER])


def test_configuration():
    with tempfile.TemporaryDirectory(prefix="svpn config ") as directory:
        base = pathlib.Path(directory)
        (base / "identity").symlink_to("/keys/client")
        events = base / "events"
        for event in ("up", "down"):
            script = base / (event + " hook")
            script.write_text(
                "#!/bin/sh\nprintf "
                + shlex.quote(event + " %s\n")
                + ' "$SVPN_TUN_NAME" >> '
                + shlex.quote(str(events))
                + "\n"
            )
            script.chmod(0o700)
        common = (
            'ssh-user = "root"\nssh-identity = "identity"\n'
            'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
            'log-level = "debug"\nmimic = ["mosh"]\n'
        )
        single = base / "single.toml"
        single.write_text(
            common + f'server = "{SERVER}"\nstats-interval = 0\n'
            'up-script = "up hook"\ndown-script = "down hook"\n'
        )
        with session("config-single", args=["svpn", "--config", str(single)]) as (process, log):
            traffic(0)
            assert events.read_text() == "up svpn0\n"
            time.sleep(2.1)
            assert "stats: last " not in log.read_text(), log.read_text()
        cleanup_verified(process)
        assert events.read_text() == "up svpn0\ndown svpn0\n"
        print("PASS TOML single: relative identity/scripts, hooks, data, stats off, cleanup")

        events.unlink()
        multi = base / "multi.toml"
        hooks = "".join(
            event
            + "-command = "
            + json.dumps("printf '" + event + ' %s\\n\' "$SVPN_TUN_NAME" >> ' + shlex.quote(str(events)))
            + "\n"
            for event in ("up", "down")
        )
        multi.write_text(
            common + hooks + "stats-interval = 1\n"
            f'[[servers]]\naddress = "{SERVER}"\nweight = 2\n'
            'udp-port-range = "61000-61009"\n'
            f'[[servers]]\naddress = "{SERVER2}"\n'
            'ssh-identity = "identity"\nudp-port-range = "62000-62009"\n'
        )
        # Both config positions use the same grammar. This run covers prefix placement.
        with session(
            "config-multi",
            args=["svpn", "--config", str(multi), "multi"],
            server_hosts=[SERVER, SERVER2],
            ready_timeout=20,
        ) as (process, log):
            until(lambda: "serving (2/2 servers ready," in log.read_text(), seconds=10)
            traffic(1)
            for host, low in [(SERVER, "61000"), (SERVER2, "62000")]:
                assert low in command(ssh_to(host) + ['pgrep -af "svpn serve"']).stdout
            until(lambda: "stats: all servers" in log.read_text())
            assert events.read_text() == "up svpn0\n"
        cleanup_verified(process, server_hosts=[SERVER, SERVER2])
        assert events.read_text() == "up svpn0\ndown svpn0\n"
        print("PASS TOML multi: inherited/per-server identity, command hooks once, stats, cleanup")

        one = base / "one.toml"
        one.write_text(common + f'stats-interval = 1\n[[servers]]\naddress = "{SERVER}"\n')
        with session("config-multi-one", args=["svpn", "multi", "--config", str(one)]) as (process, log):
            traffic(2)
            until(lambda: "stats: last " in log.read_text())
        cleanup_verified(process)
        print("PASS TOML multi: one server accepted without special setup")

        bad = base / "bad.toml"
        cases = [
            ([], common + f'server = "{SERVER}"\nunknown = true\n'),
            ([], common + f'server = "{SERVER}"\nweight = 1\n'),
            ([], common + f'server = "{SERVER}"\nup-script = ""\n'),
            ([], common + f'server = "{SERVER}"\nup-script = "up hook"\nup-command = "true"\n'),
            (
                ["multi"],
                common + f'[[servers]]\naddress = "{SERVER}"\n'
                f'[[servers]]\naddress = "{SERVER2}"\npeer-tun-name = "bad/name"\n',
            ),
        ]
        for mode, content in cases:
            bad.write_text(content)
            result = command(["svpn"] + mode + ["--config", str(bad)], check=False, timeout=3)
            assert result.returncode == 2, result.stdout
            assert not pathlib.Path("/sys/class/net/svpn0").exists(), result.stdout
        for args in [
            ["--config", str(single), "--mtu", "1280"],
            ["multi", "--config", str(multi), "--stats-interval", "30"],
            ["--config", str(single), "--up-command", "true"],
            ["perf", "--config", str(single)],
            ["serve", "--config", str(single)],
            ["client", "--server", SERVER],
        ]:
            result = command(["svpn"] + args, check=False, timeout=3)
            assert result.returncode == 2, result.stdout
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.2)
            marker = base / "unexpected hook"
            bad.write_text(
                common
                + "up-command = "
                + json.dumps("touch " + shlex.quote(str(marker)))
                + '\n[[servers]]\naddress = "127.0.0.1"\n'
                + f"ssh-port = {listener.getsockname()[1]}\n"
                + f'[[servers]]\naddress = "{SERVER2}"\npeer-tun-name = "bad/name"\n'
            )
            result = command(["svpn", "multi", "--config", str(bad)], check=False, timeout=3)
            assert result.returncode == 2, result.stdout
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError("SSH started before the second server was validated")
            assert not marker.exists() and not pathlib.Path("/sys/class/net/svpn0").exists()
        result = command(
            ["svpn", "--config", str(single)], check=False, timeout=3, preexec_fn=lambda: os.setuid(65534)
        )
        assert result.returncode == 2 and "Permission denied" in result.stdout, result.stdout
        print(
            "PASS TOML rejects mixed sources, invalid fields/hooks, unreadable file "
            "and removed client command before TUN"
        )


def test_server_hooks():
    with tempfile.TemporaryDirectory(prefix="svpn server hooks ") as directory:
        base = pathlib.Path(directory)
        (base / "identity").symlink_to("/keys/client")
        up_marker = "/tmp/svpn-server-up"
        down_marker = "/tmp/svpn-server-down"
        for marker in (up_marker, down_marker):
            command(ssh_to(SERVER) + [f"rm -f {shlex.quote(marker)}"])
        config = base / "config.toml"
        config.write_text(
            'ssh-user = "root"\nssh-identity = "identity"\n'
            'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
            'log-level = "debug"\nmimic = ["mosh"]\n'
            f'server = "{SERVER}"\nstats-interval = 0\n'
            f'server-up = "touch {up_marker} && echo up-done"\n'
            f'server-down = "touch {down_marker} && echo down-done"\n'
        )
        with session("server-hooks", args=["svpn", "--config", str(config)]) as (process, log):
            until(lambda: "vpn: started" in log.read_text(), seconds=10)
            assert up_marker in command(ssh_to(SERVER) + [f"ls {shlex.quote(up_marker)}"]).stdout
        cleanup_verified(process)
        assert down_marker in command(ssh_to(SERVER) + [f"ls {shlex.quote(down_marker)}"]).stdout
        print("PASS server hooks: up/down executed on server")

        config.write_text(
            'ssh-user = "root"\nssh-identity = "identity"\n'
            'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
            'log-level = "debug"\nmimic = ["mosh"]\n'
            f'server = "{SERVER}"\nstats-interval = 0\n'
            'server-up = "exit 1"\n'
        )
        result = command(["svpn", "--config", str(config)], check=False, timeout=10)
        assert result.returncode != 0
        assert "server up hook failed" in result.stdout
        print("PASS server hooks: up failure fails fast")


def test_authentication():
    wrong_pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    for flag, value in [("--ssh-identity", "/keys/wrong"), ("--ssh-host-key", wrong_pin)]:
        args = CLIENT.copy()
        if flag in args:
            args[args.index(flag) + 1] = value
        else:
            args += [flag, value]
        result = command(args, check=False)
        assert result.returncode != 0
        assert not pathlib.Path("/sys/class/net/svpn0").exists()
        assert ssh("test ! -e /sys/class/net/svpn0", check=False).returncode == 0
    malformed = ssh("/usr/local/bin/svpn serve", check=False, input="not JSON\n")
    assert malformed.returncode != 0
    assert ssh("test ! -e /sys/class/net/svpn0", check=False).returncode == 0
    print("PASS wrong key, wrong host-key pin and malformed JSON fail before TUN creation")


def test_known_hosts_tofu():
    # TOFU: the first connection without a pin learns the server fingerprint; tampering
    # with known_hosts closes the connection before the TUN is created.
    known = pathlib.Path("/tmp/svpn-known-hosts")
    known.unlink(missing_ok=True)
    args = CLIENT.copy()
    env = dict(os.environ, SVPN_KNOWN_HOSTS=str(known))
    with session("tofu-first", env=env, args=args) as (process, path):
        tcp_echo(1)
    cleanup_verified(process)
    entries = command(["cat", str(known)]).stdout.strip().splitlines()
    assert len(entries) == 1 and entries[0].split()[0] == f"{SERVER}:22", entries
    fingerprint = entries[0].split()[1]
    tampered = entries[0].replace(fingerprint, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    command(["sh", "-c", f'echo "{tampered}" > {known}'])
    result = command(args, check=False, env=env)
    assert result.returncode != 0, "tampered known_hosts must be rejected"
    assert not pathlib.Path("/sys/class/net/svpn0").exists()
    corrupted = ("\n".join(entries) + "\n").encode() + b"\xff"
    known.write_bytes(corrupted)
    result = command(args, check=False, env=env)
    assert result.returncode != 0, "unreadable known_hosts must be rejected"
    assert "failed to read" in result.stdout, result.stdout
    assert known.read_bytes() == corrupted, "unreadable known_hosts was overwritten"
    assert not pathlib.Path("/sys/class/net/svpn0").exists()
    assert ssh("test ! -e /sys/class/net/svpn0", check=False).returncode == 0
    print("PASS known_hosts TOFU: learn, reject mismatch and preserve unreadable records")


def test_agent_identity():
    output = command(["ssh-agent", "-s"]).stdout
    sock = re.search(r"SSH_AUTH_SOCK=([^;]+);", output).group(1)
    agent_pid = int(re.search(r"Agent pid (\d+)", output).group(1))
    try:
        command(["ssh-add", "/keys/client"], env={"SSH_AUTH_SOCK": sock, "PATH": os.environ["PATH"]})
        env = dict(os.environ, SSH_AUTH_SOCK=sock)
        # No --ssh-identity: the agent is the only key source.
        args = CLIENT.copy()
        del args[args.index("--ssh-identity") : args.index("--ssh-identity") + 2]
        with session("agent-no-flag", env=env, args=args) as (process, path):
            command(["ping", "-n", "-c", "1", "-W", "3", PEER])
            tcp_echo(1)
        cleanup_verified(process)
        assert process.returncode == 0, path.read_text()
    finally:
        os.kill(agent_pid, signal.SIGTERM)
    print("PASS ssh-agent: run without --ssh-identity")


def test_no_ssh_binary():
    # Built-in SSH: the client does not invoke an external ssh and does not need one in PATH.
    empty = pathlib.Path("/tmp/empty-path")
    empty.mkdir(exist_ok=True)
    args = ["/usr/local/bin/svpn"] + CLIENT[1:]
    with session("no-ssh-binary", env={"PATH": str(empty)}, args=args) as (process, path):
        command(["ping", "-n", "-c", "1", "-W", "3", PEER])
        tcp_echo(1)
    cleanup_verified(process)
    assert process.returncode == 0, path.read_text()
    print("PASS client works without ssh binary in PATH")


def test_custom_tun_name():
    name = "svpn-test"
    with session("custom-tun-name", tun_name=name, server_tun_name="svpn-srv") as (process, path):
        assert pathlib.Path("/sys/class/net/" + name).exists()
        assert not pathlib.Path("/sys/class/net/svpn0").exists(), "client ignored --tun-name"
        tun = json.loads(command(["ip", "-j", "addr", "show", "dev", name]).stdout)[0]
        assert any(address.get("local") == LOCAL for address in tun["addr_info"])
        server_tun = json.loads(ssh("ip -j addr show dev svpn-srv").stdout)[0]
        assert any(address.get("local") == PEER for address in server_tun["addr_info"])
        tcp_echo(3)
        command(["ping", "-n", "-c", "1", "-W", "2", PEER])
    cleanup_verified(process, tun_name=name, server_tun_name="svpn-srv")
    assert process.returncode == 0, path.read_text()
    print("PASS --tun-name/--peer-tun-name: custom TUNs carry TCP/ICMP and disappear on stop")


def test_kernel_tun_name():
    # Empty server name: the kernel creates the TUN (tun*).
    with session("kernel-tun-name", server_tun_name="", server_route=False) as (process, path):
        deadline = time.monotonic() + 8
        server_name = None
        while time.monotonic() < deadline:
            interfaces = json.loads(ssh("ip -j addr show").stdout)
            found = [
                item["ifname"]
                for item in interfaces
                if any(a.get("local") == PEER for a in item["addr_info"])
            ]
            if found:
                server_name = found[0]
                break
            time.sleep(0.05)
        assert server_name and server_name.startswith("tun"), server_name
        ssh(f"ip route replace {LOCAL}/32 dev {server_name} src {PEER}")
        command(["ping", "-n", "-c", "1", "-W", "3", PEER])
    cleanup_verified(process, server_tun_name=server_name)
    assert process.returncode == 0, path.read_text()
    print("PASS empty --peer-tun-name: kernel assigns server TUN name")


def test_log_levels():
    # error: errors only — readiness and flows are not logged.
    with session("log-error", args=CLIENT + ["--log-level", "error"], ready_by_tun=True) as (process, path):
        tcp_echo(1)
    cleanup_verified(process)
    log = path.read_text()
    assert "vpn: started" not in log and "flow_open" not in log, log
    # debug: heartbeat periodicity shows up, which is absent at info.
    with session("log-debug", args=CLIENT + ["--log-level", "debug"]) as (process, path):
        until(lambda: "heartbeat sent" in path.read_text())
    cleanup_verified(process)
    log = path.read_text()
    assert "heartbeat sent" in log and "vpn: started" in log, log
    print("PASS --log-level: error hides lifecycle, debug adds heartbeat")


def test_client_stats():
    with session("stats-info", args=CLIENT + ["--log-level", "info", "--stats-interval", "1"]) as (
        process,
        path,
    ):
        tcp_echo(1)
        until(lambda: path.read_text().count("stats: last ") >= 3)
        log = path.read_text()
        assert "servers ready 1/1" in log, log
        assert f"[{SERVER}] ready | RX " in log, log
        for field in (
            "Mbit/s",
            "packets)",
            "total RX ",
            "MiB",
            "drops +",
            " active |",
            " opened /",
            " failed /",
            " closed",
        ):
            assert field in log, (field, log)
        assert "NaN" not in log and "heartbeat sent" not in log, log
    cleanup_verified(process)
    for level, interval in [("info", "0"), ("error", "1")]:
        with session(
            "stats-off-" + level,
            args=CLIENT + ["--log-level", level, "--stats-interval", interval],
            ready_by_tun=(level == "error"),
        ) as (process, path):
            tcp_echo(1)
            time.sleep(2.2)
            assert "stats: last " not in path.read_text(), path.read_text()
        cleanup_verified(process)
    print("PASS client stats: periodic rich INFO report, 0 disables, error hides")


def test_secondary_server_address():
    # A wildcard UDP socket otherwise replies from the primary address, not this SSH destination.
    secondary = "172.30.77.4"
    ssh(f"ip addr add {secondary}/24 dev eth0")
    index = CLIENT.index("--server") + 1
    CLIENT[index] = secondary
    try:
        with session("secondary-address") as (process, _path):
            command(["ping", "-n", "-c", "1", "-W", "3", PEER])
            tcp_echo(7)
        cleanup_verified(process)
    finally:
        CLIENT[index] = SERVER
        ssh(f"ip addr del {secondary}/24 dev eth0")
    print("PASS secondary server IP: UDP replies retain the SSH destination address")


def test_readiness_requires_kernel_reply():
    # Transport probes and live SSH must not bypass a broken server TUN path.
    rule = "INPUT -i svpn0 -p icmp --icmp-type echo-request -j DROP"
    for mimic in ("mosh", "ssh"):
        ssh("iptables -w -I " + rule)
        path = LOG_DIR / ("kernel-required-" + mimic + ".log")
        args = CLIENT + ["--mimic", mimic, "--log-level", "debug"]
        if mimic == "ssh":
            args += ["--tcp-port", "41031"]
        try:
            with path.open("w") as log:
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log)
                try:
                    ssh("true")
                    assert process.wait(timeout=25) != 0, path.read_text()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
            log = path.read_text()
            assert "checking round failed" in log, log
            assert "no server available" in log, log
            assert "vpn: started" not in log, log
            assert "verified — ICMP echo round-trip" not in log, log
            cleanup_verified(process)
        finally:
            ssh("iptables -w -D " + rule)
    print("PASS kernel readiness: UDP and TCP reject live transport without TUN echo reply")


TESTS = [
    ("test_configuration", test_configuration),
    ("test_server_hooks", test_server_hooks),
    ("test_authentication", test_authentication),
    ("test_known_hosts_tofu", test_known_hosts_tofu),
    ("test_agent_identity", test_agent_identity),
    ("test_no_ssh_binary", test_no_ssh_binary),
    ("test_custom_tun_name", test_custom_tun_name),
    ("test_kernel_tun_name", test_kernel_tun_name),
    ("test_log_levels", test_log_levels),
    ("test_client_stats", test_client_stats),
    ("test_secondary_server_address", test_secondary_server_address),
    ("test_readiness_requires_kernel_reply", test_readiness_requires_kernel_reply),
]
