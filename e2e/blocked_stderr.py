"""Keep server stdin open and stderr full through a real session heartbeat timeout."""

import json
import os
import pathlib
import select
import subprocess
import time

reader, writer = os.pipe()
os.set_blocking(writer, False)
try:
    while True:
        os.write(writer, b"x" * 4096)
except BlockingIOError:
    pass
os.set_blocking(writer, True)
process = subprocess.Popen(
    ["svpn", "serve", "--tun-name", "stderr0", "--mimic", "mosh"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=writer,
    bufsize=0,
)
os.close(writer)
try:

    def send(message):
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()

    def receive():
        assert select.select([process.stdout], [], [], 3)[0], "server bootstrap timed out"
        line = process.stdout.readline()
        assert line, "server exited during bootstrap"
        return json.loads(line)

    send({"type": "hello", "version": 1, "client_ip": "10.77.0.2", "server_ip": "10.77.0.1", "mtu": 1280})
    assert receive()["type"] == "ready"
    assert receive()["type"] == "endpoints"
    assert receive()["type"] == "tun_ready"
    assert pathlib.Path("/sys/class/net/stderr0").exists(), "server did not create TUN"
    started = time.monotonic()
    send({"type": "tun_ready"})
    # No heartbeat replies, but stdin and the full stderr pipe remain open.
    assert process.wait(timeout=8) != 0, "heartbeat timeout returned success"
    assert 3 <= time.monotonic() - started < 8, "did not reach a live session timeout"
    assert not pathlib.Path("/sys/class/net/stderr0").exists(), "server TUN survived"
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=3)
    process.stdin.close()
    process.stdout.close()
    os.close(reader)
