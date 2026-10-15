"""Exercise real SSH, TUN, UDP data paths and fail-stop in Linux containers.
Test rig helpers live in _lib.py (shared with matrix.py/load.py)."""
import argparse
import concurrent.futures
import contextlib
import json
import os
import pathlib
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from _lib import (CLIENT, CLIENT_POOL, LOCAL, LOG_DIR, MTU, PEER, SERVER, SERVER2, SSH, cleanup_verified, command,
                  session, ssh, ssh_to, tcp_echo, until)
from lifecycle_hooks import run as test_lifecycle_hooks
from configuration import test_configuration

def kill_server_process():
    # Built-in SSH leaves no separate child process: losing control kills the server binary,
    # the client sees the channel Close and must stop.
    ssh('pkill -x svpn')


def scrub_firewall():
    # Idempotent scrub of fault-test rules: after a killed run (SIGKILL,
    # wrapper timeout) finally never runs and the rule leaks into the container,
    # breaking the following runs (we saw an INPUT udp DROP tearing down UDP channel probes).
    for rule in (['-p', 'tcp', '--dport', '22', '-j', 'DROP'],):
        for target in ('OUTPUT',):
            while command(['iptables', '-w', '-D', target] + rule, check=False).returncode == 0:
                pass
    for script in ('iptables -w -D OUTPUT -p udp -j DROP',
                   'iptables -w -D INPUT -p udp -j DROP'):
        while ssh(script, check=False).returncode == 0:
            pass


def drop_ssh_traffic():
    # Channel death without EOF: SSH packets vanish silently; only heartbeat can save it.
    command(['iptables', '-w', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '22', '-j', 'DROP'])


def restore_ssh_traffic():
    # Remove all copies: a run after a crash may have added a second instance.
    while command(['iptables', '-w', '-D', 'OUTPUT', '-p', 'tcp', '--dport', '22', '-j', 'DROP'],
                  check=False).returncode == 0:
        pass


def assert_client_rst_delivery():
    with socket.create_connection((PEER, 9000), timeout=5) as stream:
        stream.sendall(b'in-window-rst')
        assert stream.recv(13, socket.MSG_WAITALL) == b'in-window-rst'
        port = stream.getsockname()[1]
        query = f"ss -Htn state established '( sport = :9000 and dport = :{port} )'"
        assert ssh(query).stdout.strip(), 'target TCP socket must exist before reset'
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    # A flow_close log proves only bookkeeping; the target's timeout is 20 s.
    until(lambda: not ssh(query).stdout.strip(), seconds=4)


def test_client_rst_delivery():
    for name, options in [('mosh', ['--mimic', 'mosh']),
                          ('tcp-ssh', ['--mimic', 'ssh', '--tcp-port', '41034']),
                          ('tcp-none', ['--mimic', 'none', '--tcp-port', '41035'])]:
        with session('rst-' + name, args=CLIENT + options) as (process, path):
            assert_client_rst_delivery()
            tcp_echo(9)
            assert 'data path lost' not in path.read_text(), path.read_text()
        cleanup_verified(process)
        print(f'PASS client RST {name}: target socket closed, link remains usable')


def test_idle_tcp_teardown():
    configs = [('mosh', ['--mimic', 'mosh']),
               ('tcp-none', ['--mimic', 'none', '--tcp-port', '41036']),
               ('auto-tcp', ['--tcp-port', '41037'])]
    rule = ['OUTPUT', '-d', SERVER, '-p', 'udp', '-j', 'DROP']
    for name, options in configs:
        if name == 'auto-tcp':
            command(['iptables', '-w', '-I'] + rule)
        try:
            with session('idle-tcp-' + name, args=CLIENT + options + ['--stats-interval', '1']) as (process, path):
                remote = subprocess.Popen(SSH + [f'python3 -u /tests/idle_tcp.py {PEER}'],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True)
                try:
                    assert select.select([remote.stdout], [], [], 8)[0], 'idle target did not start'
                    assert remote.stdout.readline().strip() == 'listening'
                    with socket.create_connection((PEER, 9002), timeout=5) as client, \
                            socket.create_connection((PEER, 9002), timeout=5) as target:
                        assert recv_exact(client, 5) == b'ready'
                        assert recv_exact(target, 5) == b'ready'

                        def active_flows():
                            assert process.poll() is None and remote.poll() is None
                            counts = re.findall(r'flows (\d+) active', path.read_text())
                            return int(counts[-1]) if counts else None

                        until(lambda: active_flows() == 2)
                        # Keep the sockets and verify the 60 s idle policy, not just eventual closure.
                        time.sleep(45)
                        assert active_flows() == 2, 'TCP flows expired before the idle threshold'
                        time.sleep(16)
                        until(lambda: active_flows() == 0, seconds=14)
                        client.settimeout(4)
                        try:
                            client.sendall(b'resume')
                            received = client.recv(1)
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                        else:
                            raise AssertionError(f'idle client expected reset, received {received!r}')
                        remote.stdin.write('wake\n')
                        remote.stdin.flush()
                        output, _ = remote.communicate(timeout=8)
                        assert remote.returncode == 0 and 'target reset' in output, output
                    tcp_echo(11)
                    assert process.poll() is None
                    assert 'data path lost' not in path.read_text(), path.read_text()
                finally:
                    if remote.poll() is None:
                        try:
                            remote.communicate(timeout=6)
                        except subprocess.TimeoutExpired:
                            remote.kill()
                            remote.communicate(timeout=3)
            cleanup_verified(process)
            print(f'PASS idle TCP {name}: client and target receive reset on resumption; new flow works')
        finally:
            if name == 'auto-tcp':
                command(['iptables', '-w', '-D'] + rule)


def test_data():
    default_before = command(['ip', '-j', 'route', 'show', 'default']).stdout
    dns_before = pathlib.Path('/etc/resolv.conf').read_bytes()
    with session('data') as (process, path):
        tun = json.loads(command(['ip', '-j', 'addr', 'show', 'dev', 'svpn0']).stdout)[0]
        assert tun['mtu'] == 1280
        assert 'POINTOPOINT' in tun['flags']
        assert any(address.get('local') == LOCAL for address in tun['addr_info'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for _ in range(16):
                list(pool.map(tcp_echo, range(8)))
        counters = ssh('nstat -az TcpExtListenOverflows TcpExtListenDrops').stdout
        assert all(line.startswith('#') or line.split()[1] == '0' for line in counters.splitlines()), counters
        # v2 channels: one channel carries many flows; there are no per-flow UDP ports.
        log = path.read_text()
        requests = re.findall(r'flow_request id=(\d+)', log)
        server_opens = re.findall(r'flow_open role=server id=(\d+)', log)
        assert len(requests) == 128, len(requests)
        assert len(set(requests)) == 128, 'flow ids must be unique'
        assert len(server_opens) == 128, len(server_opens)
        print('PASS TCP: 16 batches of eight concurrent flows over shared channels, half-close')
        with socket.create_connection((PEER, 9000), timeout=5) as stream:
            stream.sendall(b'before')
            assert stream.recv(6, socket.MSG_WAITALL) == b'before'
            ssh(f'python3 /tests/forged_rst.py {stream.getsockname()[1]}')
            time.sleep(2.2)
            stream.sendall(b'after')
            assert stream.recv(5, socket.MSG_WAITALL) == b'after'
        print('PASS out-of-window TCP RST does not delete the VPN flow')

        assert_client_rst_delivery()
        print('PASS in-window TCP RST reaches the target socket within seconds')

        for size in (1, 17, 600, 1200):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                payload = b'U' * size
                for _ in range(2):
                    sock.sendto(payload, (PEER, 9000))
                    data, address = sock.recvfrom(2048)
                    assert data == payload and address == (PEER, 9000)
        print('PASS UDP: four flows and multiple packets per flow')

        command(['ping', '-n', '-c', '2', '-W', '2', PEER])
        command(['ping', '-n', '-c', '1', '-W', '2', '-M', 'do', '-s', '1252', PEER])
        oversized = command(['ping', '-n', '-c', '1', '-W', '1', '-M', 'do', '-s', '1253', PEER], check=False)
        assert oversized.returncode != 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect((PEER, 9001))
            sock.send(b'closed port')
            try:
                sock.recv(128)
                raise AssertionError('expected ICMP port-unreachable')
            except ConnectionRefusedError:
                pass
        print('PASS ICMP: echo, full-MTU packet, oversize rejection and quoted UDP error')

        # v2: both sides log local_stats every 5 ticks; the server's copy reaches the client log through the SSH tail.
        until(lambda: path.read_text().count('stats:') >= 2)
        assert re.search(r'rx_packets=[1-9]', path.read_text()), 'missing traffic statistics'
        assert command(['ip', '-j', 'route', 'show', 'default']).stdout == default_before
        assert pathlib.Path('/etc/resolv.conf').read_bytes() == dns_before
        print('PASS statistics; default route and DNS unchanged')
        # 128 echo flows + forged RST + in-window RST: the FIN pair closes via dwell (15s), not idle (60s).
        until(lambda: path.read_text().count('flow_close') >= 130, seconds=30)
        print('PASS FIN pair: every closed TCP flow ends via the 15s dwell, not the idle timer')
    cleanup_verified(process)
    assert process.returncode == 0, path.read_text()
    print('PASS explicit stop: both TUNs, UDP sockets and server process removed')


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


def test_low_fd_limit():
    """Shared UDP channel: 70 flows fit within 64 fds and heartbeat stays alive.
    Auto may choose per-flow TCP, which needs one socket per flow instead."""
    wrapped = ['bash', '-c', 'ulimit -Sn 64; ulimit -Hn 64; exec "$@"', 'bash'] + CLIENT[:] + ['--mimic', 'mosh', '--log-level', 'debug']
    with session('low-fd', args=wrapped) as (process, path):
        def connect(_):
            try:
                stream = socket.create_connection((PEER, 9000), timeout=2)
                stream.sendall(b'fd-limit-probe')
                return stream
            except OSError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            streams = [stream for stream in pool.map(connect, range(70)) if stream is not None]
        try:
            assert len(streams) == 70, f'flows failed under fd limit: {len(streams)}'
            # Verify data right away: the echo server drops the stream after 20s idle.
            streams[0].sendall(b'-after')
            got = recv_exact(streams[0], 20)
            assert got == b'fd-limit-probe-after', repr(got)
            heartbeats = path.read_text().count('heartbeat received')
            assert heartbeats >= 1
            time.sleep(2.2)
            assert path.read_text().count('heartbeat received') > heartbeats, 'heartbeat stopped'
            assert process.poll() is None, path.read_text()
            print(f'PASS low fd limit (mosh): all {len(streams)} flows live within 64 fds, heartbeat continues')
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process)


def test_ssh_loss():
    with session('ssh-loss') as (process, path):
        command(['ping', '-n', '-c', '1', '-W', '2', PEER])
        kill_server_process()
        process.wait(timeout=8)
        assert process.returncode != 0, path.read_text()
    cleanup_verified(process)
    print('PASS control loss: session stops without reconnect')


def test_heartbeat_loss():
    with session('heartbeat-loss') as (process, path):
        command(['ping', '-n', '-c', '1', '-W', '2', PEER])
        traffic = subprocess.Popen(['ping', '-n', '-q', '-i', '0.001', PEER],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            until(lambda: path.read_text().count('flow_active role=client') >= 2)
            drop_ssh_traffic()
            try:
                process.wait(timeout=8)
            finally:
                restore_ssh_traffic()
            assert process.returncode != 0
            assert 'heartbeat timeout' in path.read_text(), path.read_text()
        finally:
            traffic.send_signal(signal.SIGINT)
            output, _ = traffic.communicate(timeout=3)
        counts = re.search(r'(\d+) packets transmitted, (\d+) received', output)
        assert counts and int(counts[1]) > 100 and int(counts[2]) > 10, output
    cleanup_verified(process)
    print('PASS heartbeat loss with SSH open and continuous traffic: both sides stop')


def test_blocked_stderr():
    for failure in (kill_server_process, drop_ssh_traffic):
        with session('blocked-stderr', blocked_logs=True) as (process, _path):
            command(['ping', '-n', '-c', '1', '-W', '2', PEER])
            failure()
            try:
                process.wait(timeout=8)
            finally:
                if failure is drop_ssh_traffic:
                    restore_ssh_traffic()
            assert process.returncode != 0
        cleanup_verified(process)
    print('PASS full stderr: control loss and heartbeat loss still remove both TUNs')


def test_server_blocked_stderr():
    ssh('python3 /tests/blocked_stderr.py', timeout=20)
    assert command(SSH + ['pgrep -x svpn'], check=False).returncode == 1
    print('PASS server stderr full: live stdin, heartbeat timeout exits and removes TUN')


def test_sigkill_takeover():
    # ISSUE-stale-serve: a SIGKILLed client leaves the server serve holding
    # TUN/UDP only until its heartbeat window; the next client must take over
    # without manual cleanup (the serve TUN-busy retry absorbs the window).
    with session('sigkill-takeover') as (process, _path):
        command(['ping', '-n', '-c', '1', '-W', '2', PEER])
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=3)
    started = time.monotonic()
    until(lambda: command(ssh_to(SERVER) + ['pgrep -x svpn'], check=False).returncode == 1,
          seconds=10)
    elapsed = time.monotonic() - started
    assert elapsed <= 6, f'stale serve lived {elapsed:.1f}s'
    with session('sigkill-takeover-2', ready_timeout=15) as (second, _second_path):
        command(['ping', '-n', '-c', '1', '-W', '2', PEER])
    cleanup_verified(second)
    print(f'PASS sigkill takeover: stale serve gone in {elapsed:.1f}s, reconnect works')


def test_authentication():
    wrong_pin = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    for flag, value in [('--ssh-identity', '/keys/wrong'), ('--ssh-host-key', wrong_pin)]:
        args = CLIENT.copy()
        if flag in args:
            args[args.index(flag) + 1] = value
        else:
            args += [flag, value]
        result = command(args, check=False)
        assert result.returncode != 0
        assert not pathlib.Path('/sys/class/net/svpn0').exists()
        assert ssh('test ! -e /sys/class/net/svpn0', check=False).returncode == 0
    missing = CLIENT.copy()
    del missing[missing.index('--peer-tun-name'):missing.index('--peer-tun-name') + 2]
    assert command(missing, check=False).returncode != 0, '--peer-tun-name must be required'
    assert not pathlib.Path('/sys/class/net/svpn0').exists()
    malformed = ssh('/usr/local/bin/svpn serve', check=False, input='not JSON\n')
    assert malformed.returncode != 0
    assert ssh('test ! -e /sys/class/net/svpn0', check=False).returncode == 0
    print('PASS wrong key, wrong host-key pin, missing --peer-tun-name and malformed JSON fail before TUN creation')


def test_known_hosts_tofu():
    # TOFU: the first connection without a pin learns the server fingerprint; tampering
    # with known_hosts closes the connection before the TUN is created.
    known = pathlib.Path('/tmp/svpn-known-hosts')
    known.unlink(missing_ok=True)
    args = CLIENT.copy()
    env = dict(os.environ, SVPN_KNOWN_HOSTS=str(known))
    with session('tofu-first', env=env, args=args) as (process, path):
        tcp_echo(1)
    cleanup_verified(process)
    entries = command(['cat', str(known)]).stdout.strip().splitlines()
    assert len(entries) == 1 and entries[0].split()[0] == f'{SERVER}:22', entries
    fingerprint = entries[0].split()[1]
    tampered = entries[0].replace(fingerprint, 'SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=')
    command(['sh', '-c', f'echo "{tampered}" > {known}'])
    result = command(args, check=False, env=env)
    assert result.returncode != 0, 'tampered known_hosts must be rejected'
    assert not pathlib.Path('/sys/class/net/svpn0').exists()
    corrupted = ('\n'.join(entries) + '\n').encode() + b'\xff'
    known.write_bytes(corrupted)
    result = command(args, check=False, env=env)
    assert result.returncode != 0, 'unreadable known_hosts must be rejected'
    assert 'failed to read' in result.stdout, result.stdout
    assert known.read_bytes() == corrupted, 'unreadable known_hosts was overwritten'
    assert not pathlib.Path('/sys/class/net/svpn0').exists()
    assert ssh('test ! -e /sys/class/net/svpn0', check=False).returncode == 0
    print('PASS known_hosts TOFU: learn, reject mismatch and preserve unreadable records')


def test_agent_identity():
    output = command(['ssh-agent', '-s']).stdout
    sock = re.search(r'SSH_AUTH_SOCK=([^;]+);', output).group(1)
    agent_pid = int(re.search(r'Agent pid (\d+)', output).group(1))
    try:
        command(['ssh-add', '/keys/client'], env={'SSH_AUTH_SOCK': sock, 'PATH': os.environ['PATH']})
        env = dict(os.environ, SSH_AUTH_SOCK=sock)
        # Two scenarios: an explicit .pub key and no --ssh-identity at all — the agent
        # remains the only key source.
        for label, mutate in [
            ('identity.pub', lambda a: a.__setitem__(a.index('--ssh-identity') + 1, '/keys/client.pub')),
            ('no-flag', lambda a: a.__delitem__(slice(a.index('--ssh-identity'), a.index('--ssh-identity') + 2))),
        ]:
            args = CLIENT.copy()
            mutate(args)
            with session(f'agent-{label}', env=env, args=args) as (process, path):
                command(['ping', '-n', '-c', '1', '-W', '3', PEER])
                tcp_echo(1)
            cleanup_verified(process)
            assert process.returncode == 0, path.read_text()
    finally:
        os.kill(agent_pid, signal.SIGTERM)
    print('PASS ssh-agent: .pub key and run without --ssh-identity')


def test_no_ssh_binary():
    # Built-in SSH: the client does not invoke an external ssh and does not need one in PATH.
    empty = pathlib.Path('/tmp/empty-path')
    empty.mkdir(exist_ok=True)
    args = ['/usr/local/bin/svpn'] + CLIENT[1:]
    with session('no-ssh-binary', env={'PATH': str(empty)}, args=args) as (process, path):
        command(['ping', '-n', '-c', '1', '-W', '3', PEER])
        tcp_echo(1)
    cleanup_verified(process)
    assert process.returncode == 0, path.read_text()
    print('PASS client works without ssh binary in PATH')


def test_secondary_server_address():
    # A wildcard UDP socket otherwise replies from the primary address, not this SSH destination.
    secondary = '172.30.77.4'
    ssh(f'ip addr add {secondary}/24 dev eth0')
    index = CLIENT.index('--server') + 1
    CLIENT[index] = secondary
    try:
        with session('secondary-address') as (process, _path):
            command(['ping', '-n', '-c', '1', '-W', '3', PEER])
            tcp_echo(7)
        cleanup_verified(process)
    finally:
        CLIENT[index] = SERVER
        ssh(f'ip addr del {secondary}/24 dev eth0')
    print('PASS secondary server IP: UDP replies retain the SSH destination address')


def pool_args():
    # Weights 2:1 — smooth WRR: flows 1,2→SERVER, 3→SERVER2, deterministically.
    args = [CLIENT[0], 'multi'] + CLIENT[1:]
    args[args.index('--server') + 1] = f'{SERVER},weight=2'
    return args + ['--server', SERVER2]


def test_hostname_servers():
    hosts = pathlib.Path('/etc/hosts')
    original = hosts.read_text()
    name, ipv6_only = 'svpn-reconnect.test', 'svpn-ipv6.test'
    loopback = 'svpn-loopback.test'
    secondary = '172.30.77.6'
    drop = ['iptables', '-w', '-A', 'OUTPUT', '-d', SERVER, '-p', 'tcp',
            '--dport', '41026', '-j', 'DROP']
    undrop = drop[:2] + ['-D'] + drop[3:]
    known = pathlib.Path('/tmp/hostname-known-hosts')
    known.unlink(missing_ok=True)
    env = dict(os.environ, SVPN_KNOWN_HOSTS=str(known))
    ssh(f'ip addr add {secondary}/24 dev eth0')
    try:
        records = original + f'\n::1 {ipv6_only}\n127.0.0.1 {loopback}\n'
        hosts.write_text(records + f'{SERVER} {name}\n')
        args = CLIENT.copy()
        for host, reason in [(ipv6_only, 'no IPv4 addresses'),
                             (loopback, 'not a unicast IPv4 address')]:
            args[args.index('--server') + 1] = host
            result = command(args, check=False, timeout=20)
            assert result.returncode != 0 and reason in result.stdout, result.stdout
            assert 'connecting to' not in result.stdout, result.stdout
            assert not pathlib.Path('/sys/class/net/svpn0').exists()
            print(f'PASS hostname: {reason} fails before SSH/TUN')

        args[args.index('--server') + 1] = name
        result = command(args + ['--ssh-host-key', 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
                         check=False, timeout=20)
        assert result.returncode != 0 and 'host key rejected' in result.stdout, result.stdout
        assert not pathlib.Path('/sys/class/net/svpn0').exists()
        print('PASS hostname: host-key pin mismatch is still rejected')

        for mode, flags in [('auto', []), ('tcp', ['--mimic', 'ssh', '--tcp-port', '41026'])]:
            hosts.write_text(records + f'{SERVER} {name}\n')
            args = pool_args() + flags
            args[args.index('--server') + 1] = f'{name.upper()},weight=2'
            with session(f'hostname-reconnect-{mode}', args=args, env=env,
                         server_hosts=[SERVER, SERVER2], ready_timeout=30) as (process, path):
                until(lambda: 'serving (2/2 servers ready,' in path.read_text(), seconds=15)
                assert f'resolved {name} to {SERVER}' in path.read_text()
                tcp_echo(7)
                hosts.write_text(records + f'{secondary} {name}\n')
                if mode == 'tcp':
                    # SSH stays reachable; stale data connections must not work.
                    command(drop)
                kill_server_process()
                until(lambda: f'resolved {name} to {secondary}' in path.read_text(), seconds=30)
                until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 2, seconds=30)
                ssh(f'ip route replace {LOCAL}/32 dev svpn0 src {PEER}')
                for index in range(3):
                    tcp_echo(index)
                assert process.poll() is None, path.read_text()
            cleanup_verified(process, server_hosts=[SERVER, SERVER2])
            entries = known.read_text().splitlines()
            assert any(line.startswith(f'{name}:22 ') for line in entries), entries
            assert not any(line.startswith(f'{secondary}:22 ') for line in entries), entries
            print(f'PASS hostname {mode}: reconnect uses new IP for SSH/data; TOFU keeps the name')
    finally:
        while command(undrop, check=False).returncode == 0:
            pass
        hosts.write_text(original)
        ssh(f'ip addr del {secondary}/24 dev eth0')


def test_pool_two_servers():
    with session('pool-two', args=pool_args(), server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        until(lambda: 'serving (2/2 servers ready,' in path.read_text(), seconds=10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(tcp_echo, range(30)))
        log = path.read_text()
        assert f'[server {SERVER}]' in log and f'[server {SERVER2}]' in log, \
            'both servers must relay stderr with a host tag'
        first = len(re.findall(rf'\[server {SERVER}\].*flow_open role=server', log))
        second = len(re.findall(rf'\[server {SERVER2}\].*flow_open role=server', log))
        assert (first, second) == (20, 10), (first, second)
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS pool distribution: 2:1 weights split 30 flows exactly 20/10')


def test_pool_udp_ports():
    # Per-server udp-ports= must reach the remote serve command line (each
    # host gets its own non-overlapping range) and carry traffic.
    args = ['svpn', 'multi',
           f'--server', f'{SERVER},user=root,identity=/keys/client,udp-ports=61000-61009',
           f'--server', f'{SERVER2},user=root,identity=/keys/client,udp-ports=62000-62009',
           '--peer-tun-name', 'svpn0', '--tun-name', 'svpn0']
    with session('pool-ports', args=args, server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        until(lambda: 'serving (2/2 servers ready,' in path.read_text(), seconds=10)
        tcp_echo(0)
        for host, low in ((SERVER, '61000'), (SERVER2, '62000')):
            until(lambda host=host, low=low: low in command(
                ssh_to(host) + ['pgrep -af "svpn serve"'], check=False).stdout)
        log = path.read_text()
        assert f'[server {SERVER}]' in log and f'[server {SERVER2}]' in log
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS pool udp ports: per-server ranges reach both serve processes')


def test_pool_failover():
    with session('pool-failover', args=pool_args(), server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 1, seconds=10)

        def flows_on(server):
            # Tagged relayed server logs: `[server X] flow_active role=server id=N`.
            return len(re.findall(rf'\[server {re.escape(server)}\].*flow_active role=server',
                                  path.read_text()))

        # Which stream rides which server is WRR+SYN-retry nondeterministic:
        # keep connecting until BOTH servers visibly own at least one flow.
        streams = []
        try:
            while flows_on(SERVER2) == 0 or flows_on(SERVER) == 0:
                stream = socket.create_connection((PEER, 9000), timeout=15)
                streams.append(stream)
                stream.sendall(b'x')
                stream.settimeout(10)
                assert stream.recv(1) == b'x', 'echo must arrive'
                assert len(streams) < 12, 'never placed a flow on SERVER2'
            victims_expected = flows_on(SERVER2)
            # Killing the remote binary closes the SSH channel: fast, deterministic loss.
            # Count-based waits: a bare substring would match the stale bootstrap-phase
            # serving/link lines that precede the steady 2/2 state.
            command(ssh_to(SERVER2) + ['pkill', '-x', 'svpn'])
            until(lambda: path.read_text().count('serving (1/2 servers ready,') >= 2, seconds=15)
            until(lambda: 'link failed' in path.read_text(), seconds=5)
            # Retired flows reset fast instead of hanging on retransmits;
            # survivors keep echoing fresh bytes.
            victims = survivors = 0
            for stream in streams:
                stream.settimeout(10)
                try:
                    stream.sendall(b'y')
                    assert stream.recv(1) == b'y', 'surviving flow must still echo'
                    survivors += 1
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    victims += 1
                stream.close()
            assert victims == victims_expected, (victims, victims_expected)
            assert survivors >= 1
            tcp_echo(2)  # new flows go to the surviving server
            # The supervisor restarts the server binary over SSH and rejoins the pool.
            until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 2, seconds=45)
            tcp_echo(3)
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS pool failover: RST for retired flows, survivor serves, link rejoins')


def test_pool_backoff():
    drop = ['iptables', '-w', '-A', 'OUTPUT', '-d', SERVER2, '-p', 'tcp',
            '--dport', '22', '-j', 'DROP']
    undrop = drop[:2] + ['-D'] + drop[3:]
    # D6: one unreachable server must not block bootstrap of the other.
    # The drop goes up only after session() finished its operator routes:
    # session setup itself reaches both servers over SSH.
    with session('pool-backoff', args=pool_args(), server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        command(drop)
        try:
            tcp_echo(0)
            until(lambda: f'ssh[{SERVER2}]: retrying in 1 s' in path.read_text(), seconds=15)
            until(lambda: f'ssh[{SERVER2}]: retrying in 2 s' in path.read_text(), seconds=20)
            command(undrop)
            until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 1, seconds=30)
            tcp_echo(1)
        finally:
            while command(undrop, check=False).returncode == 0:
                pass
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS pool backoff: unreachable link retries with growing delay, joins later')


def test_pool_all_down():
    drops = [['iptables', '-w', '-A', 'OUTPUT', '-d', host, '-p', 'tcp',
              '--dport', '22', '-j', 'DROP'] for host in (SERVER, SERVER2)]
    undrops = [drop[:2] + ['-D'] + drop[3:] for drop in drops]
    for drop in drops:
        command(drop)
    # No session() here: it waits for `vpn: started`, which never happens
    # when every link is down. The VPN must exit on its own, non-zero.
    path = LOG_DIR / 'pool-all-down.log'
    try:
        with path.open('w') as log:
            process = subprocess.Popen(pool_args() + ['--log-level', 'debug'],
                                       stdout=subprocess.DEVNULL, stderr=log)
            process.wait(timeout=60)
        assert process.returncode != 0, path.read_text()
        assert 'no server available' in path.read_text(), path.read_text()
        assert not pathlib.Path('/sys/class/net/svpn0').exists(), 'client TUN survived'
    finally:
        for undrop in undrops:
            while command(undrop, check=False).returncode == 0:
                pass
        if process.poll() is None:
            process.kill()
    print('PASS pool all-down: every link lost stops the VPN with a non-zero code')


def test_custom_tun_name():
    name = 'svpn-test'
    with session('custom-tun-name', tun_name=name, server_tun_name='svpn-srv') as (process, path):
        assert pathlib.Path('/sys/class/net/' + name).exists()
        assert not pathlib.Path('/sys/class/net/svpn0').exists(), 'client ignored --tun-name'
        tun = json.loads(command(['ip', '-j', 'addr', 'show', 'dev', name]).stdout)[0]
        assert any(address.get('local') == LOCAL for address in tun['addr_info'])
        server_tun = json.loads(ssh('ip -j addr show dev svpn-srv').stdout)[0]
        assert any(address.get('local') == PEER for address in server_tun['addr_info'])
        tcp_echo(3)
        command(['ping', '-n', '-c', '1', '-W', '2', PEER])
    cleanup_verified(process, tun_name=name, server_tun_name='svpn-srv')
    assert process.returncode == 0, path.read_text()
    print('PASS --tun-name/--peer-tun-name: custom TUNs carry TCP/ICMP and disappear on stop')


def test_kernel_tun_name():
    # Empty server name: the kernel creates the TUN (tun*).
    with session('kernel-tun-name', server_tun_name='', server_route=False) as (process, path):
        deadline = time.monotonic() + 8
        server_name = None
        while time.monotonic() < deadline:
            interfaces = json.loads(ssh('ip -j addr show').stdout)
            found = [item['ifname'] for item in interfaces
                     if any(a.get('local') == PEER for a in item['addr_info'])]
            if found:
                server_name = found[0]
                break
            time.sleep(0.05)
        assert server_name and server_name.startswith('tun'), server_name
        ssh(f'ip route replace {LOCAL}/32 dev {server_name} src {PEER}')
        command(['ping', '-n', '-c', '1', '-W', '3', PEER])
    cleanup_verified(process, server_tun_name=server_name)
    assert process.returncode == 0, path.read_text()
    print('PASS empty --peer-tun-name: kernel assigns server TUN name')


def test_log_levels():
    # error: errors only — readiness and flows are not logged.
    with session('log-error', args=CLIENT + ['--log-level', 'error'], ready_by_tun=True) as (process, path):
        tcp_echo(1)
    cleanup_verified(process)
    log = path.read_text()
    assert 'vpn: started' not in log and 'flow_open' not in log, log
    # debug: heartbeat periodicity shows up, which is absent at info.
    with session('log-debug', args=CLIENT + ['--log-level', 'debug']) as (process, path):
        until(lambda: 'heartbeat sent' in path.read_text())
    cleanup_verified(process)
    log = path.read_text()
    assert 'heartbeat sent' in log and 'vpn: started' in log, log
    print('PASS --log-level: error hides lifecycle, debug adds heartbeat')


def test_client_stats():
    with session('stats-info', args=CLIENT + ['--log-level', 'info', '--stats-interval', '1']) as (process, path):
        tcp_echo(1)
        until(lambda: path.read_text().count('stats: last ') >= 3)
        log = path.read_text()
        assert 'servers ready 1/1' in log, log
        assert f'[{SERVER}] ready | RX ' in log, log
        for field in ('Mbit/s', 'packets)', 'total RX ', 'MiB', 'drops +', ' active |', ' opened /', ' failed /', ' closed'):
            assert field in log, (field, log)
        assert 'NaN' not in log and 'heartbeat sent' not in log, log
    cleanup_verified(process)
    for level, interval in [('info', '0'), ('error', '1')]:
        with session('stats-off-' + level, args=CLIENT + ['--log-level', level, '--stats-interval', interval],
                     ready_by_tun=(level == 'error')) as (process, path):
            tcp_echo(1)
            time.sleep(2.2)
            assert 'stats: last ' not in path.read_text(), path.read_text()
        cleanup_verified(process)
    print('PASS client stats: periodic rich INFO report, 0 disables, error hides')


NFT_RULES = '''table inet svpn_masq {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 10.77.0.0/24 accept
  }
  chain masq {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/24 oifname "eth0" masquerade
  }
}
'''


def test_masquerade():
    # ip_forward is preconfigured in Compose; this fixture checks administrator-supplied nftables NAT.
    ssh("mkdir -p /etc/nftables.d && cat > /etc/nftables.d/svpn.nft <<'NFT'\n" + NFT_RULES + 'NFT\nnft -f /etc/nftables.d/svpn.nft')
    assert '1' in ssh('sysctl -n net.ipv4.ip_forward').stdout.split()
    with session('masq') as (process, path):
        # The user routes the external service address into the TUN (routes are the OS's domain).
        command(['ip', 'route', 'replace', '172.30.77.4/32', 'dev', 'svpn0'])
        with socket.create_connection(('172.30.77.4', 9000), timeout=10) as stream:
            # The target sends the peer IP address and '\n' — read the whole frame.
            peer = recv_exact(stream, len(SERVER) + 1).strip()
            assert peer == SERVER.encode(), peer
            stream.sendall(b'masq-probe')
            assert recv_exact(stream, len(b'masq-probe')) == b'masq-probe'
        print('PASS masquerade: external service sees source=server IP, session alive')
    cleanup_verified(process)
    # The rules are shared across sessions and survive the stop.
    assert 'svpn_masq' in ssh('nft list tables').stdout
    print('PASS masquerade: rules survive session stop')


def server_udp_ports():
    # v2: channels share sockets; QUIC loopback releases (127.0.0.1) are internal, not counted.
    out = ssh("ss -H -uanp | grep '\"svpn\"' || true").stdout
    return {int(line.split()[3].rsplit(':', 1)[1]) for line in out.splitlines()
            if line.strip() and not line.split()[3].startswith('127.0.0.1:')}


def test_udp_port_range():
    with session('ports', args=CLIENT + ['--udp-port-range', '41000-41003']) as (process, path):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(tcp_echo, range(4)))
        ports = server_udp_ports()
        # v2 channels: one channel carries many flows; the whole range is not taken.
        assert ports and ports <= {41000, 41001, 41002, 41003}, f'flow ports left the range: {ports}'
        # The FIN dwell keeps the ports busy; once released, the second wave takes them again.
        time.sleep(17)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(tcp_echo, range(4, 8)))
        ports = server_udp_ports()
        assert ports and ports <= {41000, 41001, 41002, 41003}, f'ports left the range: {ports}'
        print('PASS port range: server flow ports stay within 41000-41003 and are reused')
    cleanup_verified(process)
    print('PASS port range: session cleaned up')


def test_tcp_transport():
    args = CLIENT + ['--mimic', 'banner', '--tcp-port', '41020']
    with session('tcp', args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert 'tcp_remote' in log, 'client did not open a TCP flow'
        assert 'tcp_accept' in log, 'server did not accept a TCP flow'
    cleanup_verified(process)
    print('PASS tcp_transport: session + data over TCP flow transport')


def test_tcp_ephemeral():
    # tcp-port 0 binds an ephemeral listener; Endpoints/Opened must announce
    # the actual port (previously the literal 0 reached the client).
    args = CLIENT + ['--mimic', 'banner', '--tcp-port', '0']
    with session('tcp-ephemeral', args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert 'tcp_remote' in log and 'tcp_accept' in log, log
    cleanup_verified(process)
    print('PASS tcp ephemeral: port 0 session carries data')


def test_tcp_udp_blocked():
    # TCP mode does not depend on UDP: with server OUTPUT UDP blocked
    # the session and flows work, and the control SSH stays alive (it is TCP itself).
    ssh('iptables -w -A OUTPUT -p udp -j DROP')
    try:
        args = CLIENT + ['--mimic', 'banner', '--tcp-port', '41025']
        with session('tcp-udp-blocked', args=args) as (process, path):
            tcp_echo(0)
            tcp_echo(1)
            assert 'tcp_remote' in path.read_text(), 'client did not open a TCP flow'
        cleanup_verified(process)
    finally:
        ssh('iptables -w -D OUTPUT -p udp -j DROP')
    print('PASS tcp_udp_blocked: TCP flows survive server-wide UDP drop')


def test_tcp_teardown():
    args = CLIENT + ['--mimic', 'none', '--tcp-port', '41021']
    with session('tcp-teardown', args=args) as (process, path):
        tcp_echo(0)
        assert 'tcp_accept' in path.read_text(), 'server did not accept a TCP flow'
    # cleanup_verified already checked: the svpn process on the server is gone, the client
    # TUN is removed and not recreated; TCP connections are closed by JoinSet::abort_all in Drop.
    cleanup_verified(process)
    assert ssh("ss -H -ltn 'sport = :41021'").stdout == '', 'TCP listener port survived'
    assert '"svpn"' not in ssh('ss -H -tanp').stdout, 'server TCP sockets survived'
    assert '"svpn"' not in command(['ss', '-H', '-tanp']).stdout, 'client TCP sockets survived'
    print('PASS tcp_teardown: listener closed, no svpn sockets on either side')


def test_tcp_l0_l1():
    # The L0/L1 difference is unit-level framing (the banner prefix in the byte stream of banner mode
    # and its absence in none: banner_then_frames_in_one_chunk, none_mode_rejects_banner_as_frame);
    # here both modes pass the full e2e.
    for name, camouflage, port in (('tcp-l0', 'none', '41022'), ('tcp-l1', 'banner', '41023')):
        args = CLIENT + ['--mimic', camouflage, '--tcp-port', port]
        with session(name, args=args) as (process, path):
            tcp_echo(0)
            tcp_echo(1)
            assert 'tcp_remote' in path.read_text(), 'client did not open a TCP flow'
        cleanup_verified(process)
    print('PASS tcp_l0_l1: none and banner camouflage both carry data end-to-end')


def test_tcp_camouflage_ssh():
    args = CLIENT + ['--mimic', 'ssh', '--tcp-port', '41024']
    with session('tcp-ssh', args=args) as (process, path):
        tcp_echo(0)
        tcp_echo(1)
        log = path.read_text()
        assert 'tcp_remote' in log, 'client did not open a TCP flow'
        assert 'tcp_accept' in log, 'server did not accept a TCP flow'
    cleanup_verified(process)
    print('PASS tcp_camouflage_ssh: session + data over SSH-lookalike camouflage')


def test_auto_tcp_fallback():
    # A TCP round winner must serve user flows without another UDP scan.
    ssh('iptables -w -A INPUT -p udp -j DROP')
    try:
        args = CLIENT
        with session('auto-udp-blocked', args=args, ready_timeout=90) as (process, path):
            preparations = path.read_text().count('channel: trying')
            tcp_echo(0)
            until(lambda: 'tcp_remote' in path.read_text(), seconds=60)
            assert path.read_text().count('channel: trying') == preparations, 'first flow retried failed UDP'
            tcp_echo(1)
            log = path.read_text()
            assert log.count('channel: trying') == preparations, 'second flow retried banned UDP'
            assert 'tcp_remote' in log, 'client did not fall back to TCP'
            assert 'tcp_accept' in log, 'server did not accept fallback flow'
            assert not re.search(r'session task failed[^\n]*cancelled', log), log
        cleanup_verified(process)
    finally:
        ssh('iptables -w -D INPUT -p udp -j DROP')
    print('PASS auto_tcp_fallback: blocked UDP falls back to TCP candidate in auto mode')


def test_auto_exhausted():
    # NoReady: one full round fails with live SSH; stop before creating TUN.
    ssh('iptables -w -A INPUT -p udp -j DROP')
    ssh('iptables -w -A INPUT -p tcp --dport 41030 -j DROP')
    try:
        args = CLIENT + ['--tcp-port', '41030']
        path = LOG_DIR / 'auto-exhausted.log'
        with path.open('w') as log:
            process = subprocess.Popen(args + ['--log-level', 'debug'],
                                       stdout=subprocess.DEVNULL, stderr=log)
            try:
                def stopped_without_tun():
                    assert not pathlib.Path('/sys/class/net/svpn0').exists(), 'TUN created before readiness'
                    return process.poll() is not None
                until(stopped_without_tun, seconds=120)
                assert process.returncode != 0, 'client exited with zero code'
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        log = path.read_text()
        assert 'checking round failed' in log, log[-2000:]
        assert 'no server available' in log, log[-2000:]
        assert 'vpn: started' not in log, log[-2000:]
        for candidate in ('quic', 'webrtc', 'obfs', 'mosh'):
            assert re.search(rf'\b{candidate}: \w+', log), log[-2000:]
        assert 'tcp: probe timeout' in log, log[-2000:]
        cleanup_verified(process)
    finally:
        ssh('iptables -w -D INPUT -p tcp --dport 41030 -j DROP')
        ssh('iptables -w -D INPUT -p udp -j DROP')
    print('PASS auto_exhausted: failed round -> NoReady stop, no TUN, both sides clean')


def test_readiness_requires_kernel_reply():
    # Transport probes and live SSH must not bypass a broken server TUN path.
    rule = 'INPUT -i svpn0 -p icmp --icmp-type echo-request -j DROP'
    for mimic in ('mosh', 'ssh'):
        ssh('iptables -w -I ' + rule)
        path = LOG_DIR / ('kernel-required-' + mimic + '.log')
        args = CLIENT + ['--mimic', mimic, '--log-level', 'debug']
        if mimic == 'ssh':
            args += ['--tcp-port', '41031']
        try:
            with path.open('w') as log:
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log)
                try:
                    ssh('true')
                    assert process.wait(timeout=25) != 0, path.read_text()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
            log = path.read_text()
            assert 'checking round failed' in log, log
            assert 'no server available' in log, log
            assert 'vpn: started' not in log, log
            assert 'verified — ICMP echo round-trip' not in log, log
            cleanup_verified(process)
        finally:
            ssh('iptables -w -D ' + rule)
    print('PASS kernel readiness: UDP and TCP reject live transport without TUN echo reply')


def test_checking_recovers_without_ssh_restart():
    args = pool_args() + ['--mimic', 'mosh']
    with session('checking-recovery', args=args, server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        until(lambda: 'serving (2/2 servers ready,' in path.read_text(), seconds=10)
        before = command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip()
        command(ssh_to(SERVER2) + ['iptables -w -I INPUT -p udp -j DROP'])
        try:
            until(lambda: f'ssh[{SERVER2}]: data path lost, control alive' in path.read_text(),
                  seconds=15)
            assert process.poll() is None, path.read_text()
            tcp_echo(23)  # The healthy server still accepts new flows.
            until(lambda: f'ssh[{SERVER2}]: checking round failed' in path.read_text(), seconds=15)
            assert command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip() == before
        finally:
            command(ssh_to(SERVER2) + ['iptables -w -D INPUT -p udp -j DROP'])
        until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 2, seconds=30)
        assert command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip() == before
        tcp_echo(24)
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS Checking: live SSH, failed round, healthy peer serves, same server process rejoins')


def test_checking_preserves_active_tcp_flows():
    args = pool_args() + ['--mimic', 'ssh', '--tcp-port', '41033']
    rule = 'INPUT -i svpn0 -p icmp --icmp-type echo-request -j DROP'
    with session('checking-active-tcp', args=args, server_hosts=[SERVER, SERVER2],
                 ready_timeout=20) as (process, path):
        until(lambda: 'serving (2/2 servers ready,' in path.read_text(), seconds=10)
        before = command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip()
        streams = []
        try:
            for _ in range(6):
                stream = socket.create_connection((PEER, 9000), timeout=15)
                streams.append(stream)
                stream.settimeout(2)
                stream.sendall(b'x')
                assert stream.recv(1) == b'x'
            # Two independent TCP data sockets on SERVER2; abort only one.
            sockets = command(['ss', '-Htn', 'state', 'established', 'dst', SERVER2,
                               'dport', '=', ':41033']).stdout.splitlines()
            assert len(sockets) == 2, sockets
            local_port = int(sockets[0].split()[-2].rsplit(':', 1)[1])
            victims = set()

            def exchange():
                for index, stream in enumerate(streams):
                    if index in victims:
                        continue
                    try:
                        stream.sendall(b'y')
                        if stream.recv(1) != b'y':
                            victims.add(index)
                    except OSError:
                        victims.add(index)
                assert len(victims) <= 1, 'Checking broke another committed flow'
                assert process.poll() is None, path.read_text()

            command(ssh_to(SERVER2) + ['iptables -w -I ' + rule])
            try:
                # Delay FlowClose so the local transport error wins the queue race.
                control_drop = ['INPUT', '-s', SERVER2, '-p', 'tcp', '--sport', '22', '-j', 'DROP']
                reset = ['OUTPUT', '-d', SERVER2, '-p', 'tcp', '--dport', '41033',
                         '--sport', str(local_port), '-j', 'REJECT', '--reject-with', 'tcp-reset']
                command(['iptables', '-w', '-I'] + control_drop)
                try:
                    command(['iptables', '-w', '-I'] + reset)
                    try:
                        exchange()
                        until(lambda: f'ssh[{SERVER2}]: data path lost, control alive' in path.read_text(), seconds=3)
                    finally:
                        command(['iptables', '-w', '-D'] + reset)
                finally:
                    command(['iptables', '-w', '-D'] + control_drop)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    exchange()
                    time.sleep(0.2)
                assert len(victims) == 1, 'aborted data socket did not retire its flow'
                assert f'ssh[{SERVER2}]: checking round failed' in path.read_text(), path.read_text()
                assert command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip() == before
                tcp_echo(25)  # New assignments still use the healthy neighbour.
            finally:
                command(ssh_to(SERVER2) + ['iptables -w -D ' + rule])
            until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 2, seconds=30)
        finally:
            for stream in streams:
                stream.close()
    cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS Checking: one TCP reset, other committed flows survive failed kernel round')


def test_perf():
    base = ['svpn', 'perf', '--server', SERVER, '--ssh-user', 'root', '--ssh-identity', '/keys/client',
            '--peer-tun-name', 'svpn0', '--tun-name', 'svpn0']

    def run_perf(extra, timeout=90, mimic='mosh'):
        log = LOG_DIR / f'perf-{mimic}-{time.monotonic_ns()}.log'
        with log.open('w') as err:
            result = subprocess.run(base + ['--mimic', mimic] + extra, text=True,
                                    stdout=subprocess.PIPE, stderr=err,
                                    timeout=timeout)
        return result, log

    def both_clean():
        assert not pathlib.Path('/sys/class/net/svpn0').exists(), 'client TUN survived'
        until(lambda: ssh('pgrep -x svpn', check=False).returncode == 1
              and not any(item['ifname'] == 'svpn0'
                          for item in json.loads(ssh('ip -j link show').stdout)))

    # Download: JSON on stdout, segments/RTT/summary, exit 0, both sides clean.
    result, log = run_perf(['-t', '3', '--json'])
    assert result.returncode == 0, log.read_text()
    report = json.loads(result.stdout)
    assert report['ready_ms'] < 20000, report
    assert report['end_summary']['sum']['median'] > 0, report
    assert report['intervals'] and report['intervals'][0]['rtt_p50_ms'] is not None, report
    both_clean()

    # Upload (-R) by time: text report to stderr.
    result, log = run_perf(['-R', '-t', '3'])
    assert result.returncode == 0, log.read_text()
    assert 'Mbps' in log.read_text()
    both_clean()

    # Bytes instead of time (-n): a quick one-shot exit.
    result, log = run_perf(['-n', '2M'], timeout=60)
    assert result.returncode == 0, log.read_text()
    both_clean()

    # W01: the old WebRTC pump delivered ~0.22 Mbit/s even without loss and RTT.
    result, log = run_perf(['-t', '6', '-i', '2', '-l', '16K', '--json'], mimic='webrtc')
    assert result.returncode == 0, log.read_text()
    report = json.loads(result.stdout)
    assert report['end_summary']['sum']['mean'] > 5, report
    both_clean()

    # W01: SCTP congestion at ~40 ms RTT must not close all four flows.
    command(['tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'netem', 'delay', '20ms'])
    server_delay = False
    try:
        ssh('tc qdisc add dev eth0 root netem delay 20ms')
        server_delay = True
        result, log = run_perf(['-P', '4', '-t', '12', '-i', '3', '-l', '1M', '--json'],
                               timeout=30, mimic='webrtc')
        assert result.returncode == 0, log.read_text()
        report = json.loads(result.stdout)
        assert report['end_summary']['sum']['mean'] > 1, report
        assert 'channel_failed' not in log.read_text(), log.read_text()
        # Each of the four flows must transfer on its own: the aggregate hides
        # three stalled streams behind one live stream. Look at the intervals after warm-up.
        intervals = report['intervals'][1:]
        assert intervals, report
        per_stream = [sum(row['streams_mbit'][i] for row in intervals) for i in range(4)]
        assert all(s > 0 for s in per_stream), per_stream
    finally:
        try:
            if server_delay:
                ssh('tc qdisc del dev eth0 root')
        finally:
            command(['tc', 'qdisc', 'del', 'dev', 'eth0', 'root'])
    both_clean()

    # Failure: unreachable SSH port -> non-zero exit with the reason in stderr, nothing leaked.
    result, log = run_perf(['--ssh-port', '1', '-t', '2'], timeout=60)
    assert result.returncode != 0
    assert 'svpn:' in log.read_text(), log.read_text()
    both_clean()
    print('PASS perf: download JSON, upload -R, -n bytes, WebRTC throughput/P4 RTT, ssh failure exit')


GROUPS = ('bootstrap', 'lifecycle-pool', 'udp', 'tcp-auto')
TESTS = [
    ('lifecycle-pool', test_lifecycle_hooks),
    ('bootstrap', test_configuration),
    ('bootstrap', test_authentication),
    ('bootstrap', test_known_hosts_tofu),
    ('bootstrap', test_agent_identity),
    ('bootstrap', test_no_ssh_binary),
    ('bootstrap', test_custom_tun_name),
    ('bootstrap', test_kernel_tun_name),
    ('bootstrap', test_log_levels),
    ('bootstrap', test_client_stats),
    ('bootstrap', test_secondary_server_address),
    ('lifecycle-pool', test_hostname_servers),
    ('lifecycle-pool', test_pool_two_servers),
    ('lifecycle-pool', test_pool_udp_ports),
    ('lifecycle-pool', test_pool_failover),
    ('lifecycle-pool', test_pool_backoff),
    ('lifecycle-pool', test_pool_all_down),
    ('udp', test_data),
    ('tcp-auto', test_client_rst_delivery),
    ('tcp-auto', test_idle_tcp_teardown),
    ('udp', test_low_fd_limit),
    ('lifecycle-pool', test_ssh_loss),
    ('lifecycle-pool', test_heartbeat_loss),
    ('lifecycle-pool', test_blocked_stderr),
    ('lifecycle-pool', test_server_blocked_stderr),
    ('lifecycle-pool', test_sigkill_takeover),
    ('udp', test_masquerade),
    ('udp', test_udp_port_range),
    ('tcp-auto', test_tcp_transport),
    ('tcp-auto', test_tcp_ephemeral),
    ('tcp-auto', test_tcp_udp_blocked),
    ('tcp-auto', test_tcp_teardown),
    ('tcp-auto', test_tcp_l0_l1),
    ('tcp-auto', test_tcp_camouflage_ssh),
    ('tcp-auto', test_auto_tcp_fallback),
    ('tcp-auto', test_auto_exhausted),
    ('bootstrap', test_readiness_requires_kernel_reply),
    ('lifecycle-pool', test_checking_recovers_without_ssh_restart),
    ('lifecycle-pool', test_checking_preserves_active_tcp_flows),
    ('udp', test_perf),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ('all',) + GROUPS
    parser.add_argument('--group', choices=choices,
                        default=os.environ.get('SVPN_TEST_GROUP', 'all'))
    group = parser.parse_args().group
    if group not in choices:
        parser.error('invalid SVPN_TEST_GROUP')
    scrub_firewall()
    for rule in (['-d', SERVER, '-p', 'tcp', '--dport', '22', '-j', 'DROP'],):
        while command(['iptables', '-w', '-D', 'OUTPUT'] + rule, check=False).returncode == 0:
            pass
    for owner, test in TESTS:
        if group == 'all' or owner == group:
            test()
    label = 'ALL' if group == 'all' else group.upper()
    print(f'{label} COMPOSE TESTS PASSED', flush=True)


if __name__ == '__main__':
    main()
