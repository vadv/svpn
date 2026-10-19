"""Diagnose the mosh strategy in Compose (standalone, without importing integration):
bring up a session like matrix.py, capture ss on both sides, try a connect."""
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _lib import CLIENT, PEER, session, ssh

STRATEGY = os.environ.get('DIAG_STRATEGY', 'mosh')
with session('diag-mosh', args=CLIENT + ['--mimic', STRATEGY]) as (process, path):
    time.sleep(2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.5)
    try:
        sock.connect((PEER, 9000))
        sock.sendall(b'ping')
        print('connect ok:', sock.recv(4))
    except Exception as exc:
        print('connect failed:', exc)
    sock.close()
    print('=== server ps ===')
    print(ssh('ps -eo pid,ppid,cmd | grep -E "svpn|sshd" | grep -v grep').stdout)
    print('=== server ss full ===')
    print(ssh('ss -uanp').stdout)
    print('=== client ss full ===')
    print(subprocess.run(['ss', '-uanp'], text=True, capture_output=True).stdout)
    time.sleep(4.5)
    print('=== log ===')
    for line in path.read_text().splitlines():
        keys = ('channel', 'probe', 'bind', 'Port', 'endpoint', 'Endpoints', 'unwrap', 'wrap')
        if any(k in line for k in keys):
            print(line)
