"""Shared helpers of the Compose test rig: addresses, ssh, waits and session setup.
Used by integration.py, matrix.py, load.py and the diag scripts.
Field scripts (remote.py) live in a different environment and are out of scope here."""

import contextlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import time

SERVER = "172.30.77.2"
SERVER2 = "172.30.77.5"
LOCAL = "10.77.0.2"
PEER = "10.77.0.1"
MTU = 1280
LOG_DIR = pathlib.Path(os.environ.get("SVPN_TEST_LOG_DIR", "/tmp"))
SSH = [
    "ssh",
    "-T",
    "-i",
    "/keys/client",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "UserKnownHostsFile=/keys/known_hosts",
    "root@" + SERVER,
]


def ssh_to(host):
    return [
        "ssh",
        "-T",
        "-i",
        "/keys/client",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=/keys/known_hosts",
        "root@" + host,
    ]


SSH2 = ssh_to(SERVER2)
CLIENT = [
    "svpn",
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
CLIENT_POOL = [
    "svpn",
    "multi",
    "--server",
    f"{SERVER},user=root,identity=/keys/client",
    "--server",
    f"{SERVER2},user=root,identity=/keys/client",
    "--peer-tun-name",
    "svpn0",
    "--tun-name",
    "svpn0",
]


def command(args, check=True, timeout=90, **kwargs):
    result = subprocess.run(
        args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, **kwargs
    )
    if check and result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}")
    return result


def ssh(script, **kwargs):
    return command(SSH + [script], **kwargs)


def until(condition, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError("deadline exceeded")


@contextlib.contextmanager
def session(
    name,
    blocked_logs=False,
    tun_name="svpn0",
    server_tun_name="svpn0",
    env=None,
    args=None,
    server_route=True,
    ready_by_tun=False,
    ready_timeout=8,
    server_hosts=None,
    client_route=True,
):
    path = LOG_DIR / (name + ".log")
    with path.open("w") as log:
        blocked_read = None
        if blocked_logs:
            blocked_read, blocked_write = os.pipe()
            os.set_blocking(blocked_write, False)
            try:
                while True:
                    os.write(blocked_write, b"x" * 4096)
            except BlockingIOError:
                pass
            os.set_blocking(blocked_write, True)
        args = (args or CLIENT).copy()
        # Config fixtures already specify logging and TUN names: never mix sources.
        if "--config" not in args:
            if "--log-level" not in args:
                args += ["--log-level", "debug"]
            args[args.index("--tun-name") + 1] = tun_name
            args[args.index("--peer-tun-name") + 1] = server_tun_name
        process = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=blocked_write if blocked_logs else log,
            env=env if env is not None else os.environ.copy(),
        )
        if blocked_logs:
            os.close(blocked_write)
        try:

            def ready():
                assert process.poll() is None, path.read_text()
                if blocked_logs or ready_by_tun:
                    return pathlib.Path("/sys/class/net/" + tun_name).exists()
                return "vpn: started" in path.read_text()

            until(ready, seconds=ready_timeout)
            # These commands represent the operator, not VPN route management.
            if client_route:
                command(["ip", "route", "replace", PEER + "/32", "dev", tun_name, "src", LOCAL])
            if server_route:
                for host in server_hosts if server_hosts is not None else [SERVER]:
                    command(ssh_to(host) + [f"ip route replace {LOCAL}/32 dev {server_tun_name} src {PEER}"])
            yield process, path
        except BaseException:
            print(path.read_text(), flush=True)
            raise
        finally:
            # Remove the route before terminate: torn SSH blackholes the ssh host
            # through the dying svpn0.
            if client_route:
                subprocess.run(
                    ["ip", "route", "del", PEER + "/32", "dev", tun_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if blocked_read is not None:
                os.close(blocked_read)


def cleanup_verified(process, tun_name="svpn0", server_tun_name="svpn0", server_hosts=None):
    assert process.poll() is not None
    assert not pathlib.Path("/sys/class/net/" + tun_name).exists(), "client TUN survived"
    hosts = server_hosts if server_hosts is not None else [SERVER]

    def server_clean(host):
        interfaces = json.loads(command(ssh_to(host) + ["ip -j link show"]).stdout)
        return (
            not any(item["ifname"] == server_tun_name for item in interfaces)
            and command(ssh_to(host) + ["pgrep -x svpn"], check=False).returncode == 1
        )

    try:
        for host in hosts:
            until(lambda host=host: server_clean(host))
    except AssertionError:
        processes = command(SSH + ["ps -o pid,ppid,stat,args -C svpn"], check=False).stdout
        raise AssertionError("server cleanup failed:\n" + processes) from None
    for host in hosts:
        sockets = command(ssh_to(host) + ["ss", "-H", "-uanp"]).stdout
        assert '"svpn"' not in sockets, "server UDP sockets survived"
    assert '"svpn"' not in command(["ss", "-H", "-uanp"]).stdout, "client UDP sockets survived"
    time.sleep(0.3)
    assert not pathlib.Path("/sys/class/net/" + tun_name).exists(), "client restarted"


def tcp_echo(index, timeout=15):
    payload = bytes([index]) * 65536
    with socket.create_connection((PEER, 9000), timeout=timeout) as stream:
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        received = bytearray()
        while chunk := stream.recv(65536):
            received.extend(chunk)
    assert received == payload + b"EOF", "TCP transfer or half-close failed"


def recv_exact(stream, count, seconds=20):
    """MSG_WAITALL with SO_RCVTIMEO returns partial data — read in a loop."""
    deadline = time.monotonic() + seconds
    data = bytearray()
    while len(data) < count:
        stream.settimeout(max(0.1, deadline - time.monotonic()))
        chunk = stream.recv(count - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def assert_client_rst_delivery():
    with socket.create_connection((PEER, 9000), timeout=5) as stream:
        stream.sendall(b"in-window-rst")
        assert stream.recv(13, socket.MSG_WAITALL) == b"in-window-rst"
        port = stream.getsockname()[1]
        query = f"ss -Htn state established '( sport = :9000 and dport = :{port} )'"
        assert ssh(query).stdout.strip(), "target TCP socket must exist before reset"
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    # A flow_close log proves only bookkeeping; the target's timeout is 20 s.
    until(lambda: not ssh(query).stdout.strip(), seconds=4)
