"""Measure one Docker client against one authorized SSH server.

No server mesh, firewall changes, default-route changes, or authorized_keys edits.
A public identity selects an existing SSH-agent key; no private key enters Docker.
Run `selftest` before `run`. The SSH-agent socket must exist inside the Docker VM.
"""

import argparse
import base64
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

LOCAL, PEER = "10.77.0.2", "10.77.0.1"
SIZE = 64 * 1024 * 1024

SNAPSHOT = r"""
import hashlib,json,pathlib,re,shutil,subprocess
out={}
for key,args in [('links',['ip','-j','addr']),
                 ('routes4',['ip','-j','-4','route','show','table','all']),
                 ('routes6',['ip','-j','-6','route','show','table','all']),
                 ('rules',['ip','-j','rule'])]:
    value=json.loads(subprocess.check_output(args))
    if key=='links':
        value=[{k:x[k] for k in ('ifindex','ifname','mtu','flags','addr_info') if k in x} for x in value]
        for link in value:
            for address in link['addr_info']:
                for key2 in ('valid_life_time','preferred_life_time'): address.pop(key2,None)
    out[key]=value
for path in ('/etc/resolv.conf','/root/.ssh/authorized_keys'):
    out[path]=hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
for name,args in [('iptables-save',[]),('ip6tables-save',[]),('nft',['-s','list','ruleset'])]:
    if not shutil.which(name): continue
    p=subprocess.run([name]+args,capture_output=True,text=True)
    text='\n'.join(x for x in p.stdout.splitlines() if not x.startswith('#'))
    out[name]={'code':p.returncode,'rules':re.sub(r'\[\d+:\d+\]','[counters]',text)}
p=subprocess.check_output(['ps','-eo','pid=,comm='],text=True)
out['vpn_pids']=[line.split() for line in p.splitlines()
                 if line.split()[-1] in ('openvpn','stunnel','stunnel4')]
print(json.dumps(out))
"""

CLEANUP = r"""
import os,pathlib,shutil,signal,sys,time
root=pathlib.Path(sys.argv[1])
def own():
    found=[]
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            args=(proc/'cmdline').read_bytes().split(bytes([0]))
            if os.readlink(proc/'exe')==str(root/'svpn') or str(root/'remote.py').encode() in args:
                found.append(int(proc.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError): pass
    return found
for sig in (signal.SIGTERM,signal.SIGKILL):
    for pid in own():
        try: os.kill(pid,sig)
        except ProcessLookupError: pass
    deadline=time.monotonic()+3
    while own() and time.monotonic()<deadline: time.sleep(.1)
assert not own(), 'owned processes survived cleanup'
assert not pathlib.Path('/sys/class/net/svpn0').exists(), 'TUN survived cleanup'
shutil.rmtree(root)
"""


def command(args, *, timeout=30, check=True, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise AssertionError(
            f"{args[0]} exit {result.returncode}: "
            + result.stderr.decode(errors="replace")[-2000:]
            + result.stdout.decode(errors="replace")[-2000:]
        )
    return result


def until(predicate, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("readiness/cleanup deadline exceeded")


def event(kind, **values):
    print(json.dumps({"event": kind, "time": time.time(), **values}), flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection_id = uuid.uuid4().hex
        self.sequence = 0

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/file":
            length = self.server.payload.stat().st_size
        elif self.path == "/poll":
            time.sleep(self.server.delay)
            self.sequence += 1
            body = json.dumps({"sequence": self.sequence}).encode()
            length = len(body)
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Connection-ID", self.connection_id)
        self.send_header("X-SHA256", self.server.digest)
        self.end_headers()
        if self.path == "/file":
            with self.server.payload.open("rb") as source:
                while chunk := source.read(65536):
                    self.wfile.write(chunk)
        else:
            self.wfile.write(body)


def make_server(root, bind, size=SIZE, delay=20):
    assert __import__("shutil").disk_usage(root).free > size + 16 * 1024 * 1024
    payload = root / "payload.bin"
    digest = hashlib.sha256()
    with payload.open("wb") as output:
        for offset in range(0, size, 65536):
            chunk = os.urandom(min(65536, size - offset))
            output.write(chunk)
            digest.update(chunk)
    server = http.server.ThreadingHTTPServer((bind, 0), Handler)
    server.payload, server.digest, server.delay = payload, digest.hexdigest(), delay
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def download(connection, phase):
    started = last = time.monotonic()
    received = previous = 0
    digest = hashlib.sha256()
    samples = []
    connection.request("GET", "/file")
    response = connection.getresponse()
    assert response.status == 200
    identity = response.getheader("X-Connection-ID")
    expected = response.getheader("X-SHA256")
    length = int(response.getheader("Content-Length"))
    first_byte = time.monotonic() - started
    while chunk := response.read1(65536):
        digest.update(chunk)
        received += len(chunk)
        now = time.monotonic()
        assert now - started < 300, "file transfer exceeded 300 seconds"
        if now - last >= 1:
            sample = {
                "elapsed": now - started,
                "bytes": received,
                "mib_s": (received - previous) / (now - last) / 1048576,
            }
            samples.append(sample)
            event("sample", phase=phase, **sample)
            last, previous = now, received
    elapsed = time.monotonic() - started
    assert received == length and digest.hexdigest() == expected
    response.close()
    result = {
        "bytes": received,
        "seconds": elapsed,
        "mib_s": received / elapsed / 1048576,
        "ttfb_seconds": first_byte,
        "sha256": expected,
        "connection_id": identity,
        "samples": samples,
    }
    event("download_complete", phase=phase, **result)
    return result


def measure(connection, seconds, lock_path):
    # All containers share this file: large transfers never compete with one another.
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        first = download(connection, "first")
    deadline = time.monotonic() + seconds
    polls = []
    while time.monotonic() < deadline:
        start = time.monotonic()
        connection.request("GET", "/poll")
        response = connection.getresponse()
        body = json.loads(response.read())
        assert response.status == 200 and response.getheader("X-Connection-ID") == first["connection_id"]
        assert body["sequence"] == len(polls) + 1
        response.close()
        polls.append(time.monotonic() - start)
        event("poll", sequence=len(polls), seconds=polls[-1])
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        final = download(connection, "after_polling")
    assert first["connection_id"] == final["connection_id"] and first["sha256"] == final["sha256"]
    return {"first": first, "poll_seconds": polls, "after_polling": final, "same_tcp_connection": True}


def known_host_pin(entries):
    lines = [line.split() for line in entries.splitlines() if line.strip() and not line.startswith("#")]
    # shortcut: one unmarked key per target; revisit for multi-key/certificate field tests.
    if len(lines) != 1 or len(lines[0]) < 3 or lines[0][0].startswith("@"):
        raise ValueError("known_hosts must contain exactly one unmarked key for the target")
    blob = base64.b64decode(lines[0][2], validate=True)
    if not blob:
        raise ValueError("empty host key")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def run(args):
    ip = str(ipaddress.IPv4Address(args.server))
    token = uuid.uuid4().hex[:12]
    remote, container = "/tmp/svpn-check-" + token, "svpn-remote-" + token
    base = Path(args.work).resolve()
    work, bandwidth = base / (ip + "-" + token), base / "bandwidth"
    work.mkdir(parents=True, mode=0o700)
    bandwidth.mkdir(exist_ok=True)
    binary, known, identity = (Path(x).resolve() for x in (args.binary, args.known_hosts, args.ssh_identity))
    public = identity.read_text().strip()
    assert public.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-")), "identity must be PUBLIC"
    (work / "identity.pub").write_text(public + "\n")
    host_pin = known_host_pin(command(["ssh-keygen", "-F", ip, "-f", str(known)]).stdout.decode())
    ssh = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(known),
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "root@" + ip,
    ]

    def execute(script, **kwargs):
        return command(ssh + [script], **kwargs)

    def snapshot():
        return json.loads(execute("python3 -c " + shlex.quote(SNAPSHOT)).stdout)

    def docker(*parts, **kwargs):
        return command(["docker", "exec", container, *parts], **kwargs)

    report = {
        "server": ip,
        "remote_dir": remote,
        "container": container,
        "started": time.time(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    before = snapshot()
    (work / "before.json").write_text(json.dumps(before, indent=2))
    assert all(link["ifname"] != "svpn0" for link in before["links"]), "server already has svpn0"
    for route in before["routes4"]:
        if route.get("dst", "default") != "default":
            network = ipaddress.ip_network(route["dst"], strict=False)
            assert all(ipaddress.ip_address(address) not in network for address in (LOCAL, PEER)), route
    report["ssh_connection"] = execute('printf "%s\\n" "$SSH_CONNECTION"').stdout.decode().strip()
    created = False
    client = fixture = None
    log = None
    try:
        execute(f"test ! -e /sys/class/net/svpn0 && umask 077 && mkdir {remote}")
        created = True
        execute(f"exec tee {remote}/svpn >/dev/null", input=binary.read_bytes(), timeout=60)
        execute(f"exec tee {remote}/remote.py >/dev/null", input=Path(__file__).read_bytes())
        execute(f"chmod 500 {remote}/svpn && {remote}/svpn --version")
        assert execute(f"sha256sum {remote}/svpn").stdout.decode().split()[0] == report["binary_sha256"]
        command(
            [
                "docker",
                "run",
                "-d",
                "--init",
                "--name",
                container,
                "--cap-add",
                "NET_ADMIN",
                "--device",
                "/dev/net/tun",
                "--mount",
                "type=bind,src=" + args.agent_socket + ",dst=/agent",
                "-e",
                "SSH_AUTH_SOCK=/agent",
                "-v",
                str(work) + ":/run/check:ro",
                "-v",
                str(bandwidth) + ":/bandwidth",
                "-v",
                str(Path(__file__).resolve()) + ":/remote.py:ro",
                args.image,
                "sleep",
                "3600",
            ]
        )
        log_path = work / "svpn.log"
        log = log_path.open("wb")
        client = subprocess.Popen(
            [
                "docker",
                "exec",
                container,
                "svpn",
                "--server",
                ip,
                "--ssh-user",
                "root",
                "--ssh-identity",
                "/run/check/identity.pub",
                "--ssh-host-key",
                host_pin,
                "--ssh-remote-bin",
                remote + "/svpn",
                "--peer-tun-name",
                "svpn0",
                "--tun-name",
                "svpn0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )

        def ready():
            assert client.poll() is None, log_path.read_text()
            return "vpn: started" in log_path.read_text()

        until(ready)
        docker("ip", "route", "replace", PEER + "/32", "dev", "svpn0", "src", LOCAL)
        execute(f"ip route replace {LOCAL}/32 dev svpn0 src {PEER}")
        fixture = subprocess.Popen(
            ssh + ["python3 -u " + remote + "/remote.py serve " + remote],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert select.select([fixture.stdout], [], [], 15)[0], "fixture startup timeout"
        port = json.loads(fixture.stdout.readline())["port"]
        # No ping or data-path warmup: HTTP file download is the first inner flow.
        with (work / "measurements.jsonl").open("wb") as output:
            process = subprocess.Popen(
                [
                    "docker",
                    "exec",
                    container,
                    "python3",
                    "-u",
                    "/remote.py",
                    "probe",
                    str(port),
                    str(args.seconds),
                ],
                stdout=output,
                stderr=subprocess.PIPE,
            )
            try:
                _unused, errors = process.communicate(timeout=args.seconds + 1900)
            except BaseException:
                process.kill()
                process.wait(timeout=3)
                raise
        if process.returncode:
            raise AssertionError(errors.decode(errors="replace"))
        records = [json.loads(line) for line in (work / "measurements.jsonl").read_text().splitlines()]
        report["measurements"] = next(record["result"] for record in records if record["event"] == "complete")
        report["passed"] = True
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        errors = []
        if fixture is not None:
            try:
                fixture.stdin.close()
                fixture.wait(timeout=5)
            except Exception as error:
                fixture.kill()
                fixture.wait(timeout=3)
                errors.append("fixture: " + str(error))
        try:
            query = ["docker", "ps", "-aq", "--filter", "name=^/" + container + "$"]
            if command(query).stdout.strip():
                command(["docker", "rm", "-f", container])
            assert not command(query).stdout.strip(), "test container survived cleanup"
            if client is not None:
                client.wait(timeout=8)
        except Exception as error:
            errors.append("Docker/client: " + str(error))
        if log is not None:
            log.close()
        try:
            if created:
                execute("python3 -c " + shlex.quote(CLEANUP) + " " + remote)
                after = snapshot()
                (work / "after.json").write_text(json.dumps(after, indent=2))
                report["state_differences"] = [key for key in before if before[key] != after.get(key)]
                assert not report["state_differences"], report["state_differences"]
        except BaseException as error:
            errors.append("server: " + str(error))
        report["cleanup"] = not errors
        report["finished"] = time.time()
        if errors:
            report["cleanup_errors"] = errors
        (work / "report.json").write_text(json.dumps(report, indent=2))
        print("REPORT", work / "report.json", flush=True)
        assert not errors, errors


def selftest():
    key = "192.0.2.1 ssh-ed25519 YWJj"
    assert known_host_pin("# comment\n" + key) == "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
    for entries in [
        "",
        key + "\n" + key,
        "@revoked " + key,
        "@cert-authority " + key,
        "host ssh-ed25519 !!!!",
    ]:
        try:
            known_host_pin(entries)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid known_hosts accepted")
    compile(SNAPSHOT, "<snapshot>", "exec")
    compile(CLEANUP, "<cleanup>", "exec")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        server = make_server(root, "127.0.0.1", 131072, 0.02)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            result = measure(connection, 0.04, root / "lock")
            assert result["first"]["bytes"] == 131072 and result["same_tcp_connection"]
            assert result["poll_seconds"]
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
    print("remote harness selftest PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("selftest")
    p = modes.add_parser("serve")
    p.add_argument("directory")
    p = modes.add_parser("probe")
    p.add_argument("port", type=int)
    p.add_argument("seconds", type=float)
    p = modes.add_parser("run")
    p.add_argument("--server", required=True)
    p.add_argument("--binary", required=True)
    p.add_argument(
        "--known-hosts",
        required=True,
        help="OpenSSH known_hosts with exactly one unmarked key for this server",
    )
    p.add_argument("--ssh-identity", required=True, help="public key available in the VM SSH agent")
    p.add_argument("--agent-socket", default="/run/host-services/ssh-auth.sock")
    p.add_argument("--seconds", type=int, default=900)
    p.add_argument("--image", default="svpn-test:local")
    p.add_argument("--work", default="e2e/.work/remote")
    args = parser.parse_args()
    if args.mode == "selftest":
        selftest()
    elif args.mode == "serve":
        server = make_server(Path(args.directory), PEER)
        print(json.dumps({"port": server.server_address[1]}), flush=True)
        sys.stdin.buffer.read()
        server.shutdown()
        server.server_close()
    elif args.mode == "probe":
        connection = http.client.HTTPConnection(PEER, args.port, timeout=45)
        try:
            event("complete", result=measure(connection, args.seconds, Path("/bandwidth/lock")))
        finally:
            connection.close()
    else:

        def terminate(_signal, _frame):
            raise SystemExit("terminated; cleaning up")

        signal.signal(signal.SIGTERM, terminate)
        run(args)
