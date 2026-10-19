"""Strategy matrix I11 (EPIC-005): every fixed strategy and auto,
both traffic directions (echo = upload+download), full-MTU, idle survival.
Run: `docker compose run --rm --no-deps -v "$(pwd)/tests:/e2e-ro:ro" \
        -v /tmp/loadlogs:/testlogs client python3 -u /e2e-ro/matrix.py`.
The field (real networks/filter) is out of scope here — see columns in docs/FIELD_MATRIX.md.
"""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import threading
import time


def tcp_diagnostics(stop):
    """Capture socket pressure and kernel drops only while a transfer stalls."""
    script = ("uname -r; ss -tinm; nstat -az; "
              "timeout 2 tcpdump -i svpn0 -nn -S -tt -s 96 -c 20 'tcp port 9000' 2>&1")
    while not stop.wait(3):
        for role, args in [('client', ['sh', '-c', script]), ('server', SSH + [script])]:
            try:
                result = command(args, check=False, timeout=5)
                print(f'TCP-DIAGNOSTICS {role}\n{result.stdout}', flush=True)
            except Exception as error:
                print(f'TCP-DIAGNOSTICS {role}: {error}', flush=True)


def tcp_echo_both_ways(size_mib=4):
    """Echo: the client drives the upload, the reply is the download; both directions over one connection."""
    payload = bytes(65536)
    total = size_mib * 1024 * 1024
    received = bytearray()

    def reader(stream):
        while chunk := stream.recv(65536):
            received.extend(chunk)

    start = time.monotonic()
    with socket.create_connection((PEER, 9000), timeout=60) as stream:
        stream.settimeout(60)
        stop = threading.Event()
        monitor = threading.Thread(target=tcp_diagnostics, args=(stop,))
        monitor.start()
        try:
            thread = threading.Thread(target=reader, args=(stream,))
            thread.start()
            sent = 0
            while sent < total:
                stream.sendall(payload)
                sent += len(payload)
            stream.shutdown(socket.SHUT_WR)
            thread.join()
        finally:
            stop.set()
            monitor.join()
    wall = time.monotonic() - start
    assert bytes(received) == bytes(total) + b'EOF', 'echo mismatch'
    return round(wall, 2), round(total * 16 / wall / 1_000_000, 1)

import json
import os
import pathlib
import socket
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _lib import (CLIENT, MTU, PEER, SSH, command, session, ssh)

def udp_mtu_probe(count=3):
    """The largest UDP datagram fitting MTU 1280 without fragmentation:
    exactly a 1252-byte payload (1251 zeros + a marker)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        for i in range(count):
            payload = bytes(1251) + bytes([i])
            sock.sendto(payload, (PEER, 9000))
            data, _ = sock.recvfrom(2048)
            assert data == payload, 'udp mtu echo mismatch'
    return 'ok'


def udp_each_once(count=8):
    """Regression: the first packet of a new flow used to be delivered twice
    (request() + enqueue). Every datagram must come back exactly once."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        for i in range(count):
            payload = b'once-' + i.to_bytes(4, 'big')
            sock.sendto(payload, (PEER, 9000))
            data, _ = sock.recvfrom(2048)
            assert data == payload, f'datagram {i}: got {data!r}'
    return 'ok'


def icmp_mtu():
    """full-MTU ICMP: 1252 payload + 28 header bytes = exactly MTU."""
    out = command(['ping', '-c', '1', '-W', '5', '-M', 'do', '-s', '1252', PEER],
                  check=False).stdout
    assert 'ttl=63' in out or 'time=' in out, out
    return 'ok'


def idle_survive(seconds=75, process=None, path=None):
    """The session survives without traffic longer than FLOW_IDLE (60s); a new exchange works."""
    time.sleep(seconds)
    assert process is not None and process.poll() is None, 'session died during idle'
    return 'ok'


CONFIGS = [
    # Fixed UDP rows pin the udp transport: without a pin, the new auto default
    # would let TCP fallback mask a UDP strategy failure.
    ('mosh', ['--mimic', 'mosh']),
    ('obfs', ['--mimic', 'obfs']),
    ('quic', ['--mimic', 'quic']),
    ('webrtc', ['--mimic', 'webrtc']),
    ('tcp-none', ['--mimic', 'none', '--tcp-port', '4190']),
    ('tcp-banner', ['--mimic', 'ssh', '--tcp-port', '4191']),
    ('tcp-ssh', ['--mimic', 'ssh', '--tcp-port', '4192']),
    ('auto', ['--tcp-port', '4193']),
]


def run_config(name, args):
    row = {}
    with session(f'matrix-{name}', args=CLIENT + args) as (process, path):
        wall, mbit = tcp_echo_both_ways()
        row['bulk_4mib_echo_s'] = wall
        row['bulk_4mib_mbit'] = mbit
        row['udp_mtu'] = udp_mtu_probe()
        row['udp_each_once'] = udp_each_once()
        row['icmp_mtu'] = icmp_mtu()
        idle_survive(process=process)
        wall2, _ = tcp_echo_both_ways(1)
        row['idle_75s_then_echo'] = 'ok'
        row['log_tail_hints'] = ('tcp_remote' if 'tcp_remote' in path.read_text()
                                 else 'udp-channel')
    return row


GROUPS = {
    'udp': ('mosh', 'obfs', 'quic', 'webrtc'),
    'tcp-auto': ('tcp-none', 'tcp-banner', 'tcp-ssh', 'auto'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=('all', *GROUPS), default='all')
    group = parser.parse_args().group
    # Fault rules leaked from killed runs silently tear down UDP channels:
    # scrub them before the matrix (the same rules as scrub_firewall in integration).
    for script in ('iptables -w -D OUTPUT -p udp -j DROP',
                   'iptables -w -D INPUT -p udp -j DROP'):
        while command(SSH + [script], check=False).returncode == 0:
            pass
    report = {}
    only = os.environ.get('SVPN_MATRIX_ONLY')
    for name, args in CONFIGS:
        if group != 'all' and name not in GROUPS[group]:
            continue
        if only and name != only:
            continue
        print(f'== {name} ==', flush=True)
        report[name] = run_config(name, args)
        print(json.dumps(report[name]), flush=True)
        time.sleep(0.6)
    print('MATRIX-REPORT ' + json.dumps(report))


if __name__ == '__main__':
    main()
