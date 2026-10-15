"""Diagnose all-transports-blocked shutdown without expecting a ready TUN.
Run: docker compose run --rm --no-deps client python3 /tests/diag_exhausted.py
"""
import glob
import os
import subprocess
import time

SERVER = os.environ['SERVER'] if 'SERVER' in os.environ else '172.30.77.2'
SSH = ['ssh', '-T', '-i', '/keys/client', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/keys/known_hosts',
       'root@' + SERVER]
CLIENT = ['svpn', '--server', SERVER, '--ssh-user', 'root', '--ssh-identity', '/keys/client',
          '--peer-tun-name', 'svpn0', '--tun-name', 'svpn0']


def ssh(script, **kwargs):
    result = subprocess.run(SSH + [script], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20, **kwargs)
    if result.returncode:
        raise AssertionError(f'{script}: exit {result.returncode}\n{result.stdout}')
    return result


def main():
    ssh('iptables -w -A INPUT -p udp -j DROP')
    ssh('iptables -w -A INPUT -p tcp --dport 41030 -j DROP')
    try:
        args = CLIENT + ['--tcp-port', '41030']
        log = open('/tmp/exhausted.log', 'w')
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log)
        start = time.monotonic()
        while time.monotonic() - start < 90:
            if process.poll() is not None:
                text = open('/tmp/exhausted.log').read()
                print(f'EXITED rc={process.returncode} after {time.monotonic()-start:.0f}s')
                break
            time.sleep(2)
        else:
            print('STILL ALIVE after 90s')
            text = open('/tmp/exhausted.log').read()
            stopped = text.count('VPN stopped')
            print(f'VPN stopped lines: {stopped}')
            for task in sorted(glob.glob(f'/proc/{process.pid}/task/*/wchan')):
                print('wchan', open(task).read().strip())
            process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        text = open('/tmp/exhausted.log').read()
        interesting = [line for line in text.splitlines()
                       if 'local_stats' not in line and 'heartbeat' not in line]
        print(f'--- {len(interesting)} non-stats lines (last 45):')
        print('\n'.join(interesting[-45:]))
    finally:
        ssh('iptables -w -D INPUT -p tcp --dport 41030 -j DROP')
        ssh('iptables -w -D INPUT -p udp -j DROP')


main()
