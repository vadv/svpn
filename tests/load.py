"""I10 measurements (EPIC-005): time-to-ready, throughput/CPU/RAM/FD,
wire overhead, behavior under loss. Run:
`docker compose run --rm --no-deps client python3 -u /tests/load.py`.
"""
import json
import os
import pathlib
import socket
import statistics
import subprocess
import threading
import time

def server_pid():
    result = ssh("for p in /proc/[0-9]*; do "
                 "grep -qa svpn $p/comm 2>/dev/null && basename $p; done; true")
    pids = result.stdout.split()
    assert len(pids) == 1, f"expected one svpn process, got {pids}"
    return int(pids[0])

import json
import os
import pathlib
import socket
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _lib import (LOCAL, PEER, session, ssh)

def proc_sample(pid):
    def read(name):
        return ssh(f"cat /proc/{pid}/{name}").stdout.strip()

    stat = read("stat").rsplit(")", 1)[1].split()
    utime, stime = int(stat[11]), int(stat[12])
    rss = int(read("status").split("VmRSS:")[1].split()[0])
    fds = len(ssh(f"ls /proc/{pid}/fd").stdout.split())
    return {"cpu_ticks": utime + stime, "rss_kb": rss, "fds": fds}


def time_to_ready(runs=10):
    times = []
    for i in range(runs):
        start = time.monotonic()
        with session(f"load-ready-{i}"):
            times.append(time.monotonic() - start)
        time.sleep(0.6)  # sshd releases the previous run's connection
    return {"p50_s": round(statistics.median(times), 3),
            "p95_s": round(sorted(times)[int(0.95 * runs) - 1], 3),
            "min_s": round(min(times), 3), "max_s": round(max(times), 3), "runs": runs}


def bulk(size_mib, rate_mbit=None, seconds_cap=120):
    # The echo server writes the echo back at the same pace: without a parallel
    # reader the buffers overflow and the echo handler dies on settimeout(20) → RST.
    payload = bytes(65536)
    total = size_mib * 1024 * 1024
    interval = 65536 * 8 / (rate_mbit * 1_000_000) if rate_mbit else 0
    received = bytearray()

    def reader(stream):
        while chunk := stream.recv(65536):
            received.extend(chunk)

    pid = server_pid()
    pid0 = proc_sample(pid)
    start = time.monotonic()
    with socket.create_connection((PEER, 9000), timeout=seconds_cap) as stream:
        stream.settimeout(seconds_cap)
        thread = threading.Thread(target=reader, args=(stream,))
        thread.start()
        sent = 0
        while sent < total:
            stream.sendall(payload)
            sent += len(payload)
            if interval:
                time.sleep(interval)
        stream.shutdown(socket.SHUT_WR)
        thread.join()
    assert bytes(received) == bytes(size_mib * 1024 * 1024) + b'EOF', 'echo mismatch'
    wall = time.monotonic() - start
    pid1 = proc_sample(pid)
    ticks = pid1["cpu_ticks"] - pid0["cpu_ticks"]  # USER_HZ=100
    return {
        "size_mib": size_mib, "rate_cap_mbit": rate_mbit, "wall_s": round(wall, 2),
        "throughput_mbit": round(total * 8 / wall / 1e6, 2),
        "server_cpu_s": round(ticks / 100, 2),
        "server_cpu_pct": round(ticks / 100 / wall * 100, 1),
        "server_rss_mb": round(pid1["rss_kb"] / 1024, 1),
        "server_fds": pid1["fds"],
    }


PORT_RANGE = "60000:60009"  # default from src/main.rs DEFAULT_PORT_RANGE (iptables: dpts:…)


def wire_overhead(size_mib=32):
    spec = f"-p udp --dport {PORT_RANGE} -j ACCEPT"
    ssh(f"iptables -w -I INPUT 1 {spec}")
    try:
        result = bulk(size_mib)
        lines = ssh("iptables -w -L INPUT -v -n -x").stdout.splitlines()
    finally:
        ssh(f"iptables -w -D INPUT {spec}")
    wire = 0
    for line in lines:
        if PORT_RANGE in line:
            # -v: pkts bytes target prot … — bytes are the second field.
            wire += int(line.split()[1])
    inner = size_mib * 1024 * 1024
    result.update({"wire_bytes": wire, "inner_bytes": inner,
                   "overhead_pct": round((wire - inner) / inner * 100, 1)})
    return result


def loss_run(drop_pct):
    spec = (f"-p udp --dport {PORT_RANGE} "
            f"-m statistic --mode random --probability {drop_pct / 100} -j DROP")
    ssh(f"iptables -w -I INPUT 1 {spec}")
    try:
        result = bulk(16)
    finally:
        ssh(f"iptables -w -D INPUT {spec}")
    result["drop_pct"] = drop_pct
    return result


def main():
    report = {}
    print("== time_to_ready ==", flush=True)
    report["time_to_ready"] = time_to_ready()
    print(json.dumps(report["time_to_ready"]), flush=True)
    with session("load-bulk"):
        for name, fn in [
            ("bulk_uncapped_64mib", lambda: bulk(64)),
            ("paced_1mbit", lambda: bulk(8, rate_mbit=1)),
            ("paced_30mbit", lambda: bulk(64, rate_mbit=30)),
            ("wire_overhead", lambda: wire_overhead()),
            ("loss_2pct", lambda: loss_run(2)),
            ("loss_10pct", lambda: loss_run(10)),
        ]:
            print(f"== {name} ==", flush=True)
            report[name] = fn()
            print(json.dumps(report[name]), flush=True)
    print("LOAD-REPORT " + json.dumps(report))


if __name__ == '__main__':
    main()
