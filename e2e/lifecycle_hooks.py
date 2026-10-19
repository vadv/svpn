"""Exercise local hooks against real Linux TUNs; never touch the host network."""
import contextlib
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
from shlex import quote

from _lib import (CLIENT, CLIENT_POOL, LOCAL, LOG_DIR, PEER, SERVER, SERVER2, cleanup_verified,
                  command, session, ssh, ssh_to, tcp_echo, until)


def record(directory, body=''):
    return ('set -eu; test -d /sys/class/net/"$SVPN_TUN_NAME"; '
            'printf "%s|%s|%s|%s\\n" "$SVPN_EVENT" "$SVPN_TUN_NAME" '
            '"$SVPN_TUN_ADDR" "$SVPN_PEER_ADDR" >> ' + quote(str(directory / 'events'))
            + '; ' + body)


def verify_events(directory, events, name='svpn0'):
    rows = [line.split('|') for line in (directory / 'events').read_text().splitlines()]
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
    path = LOG_DIR / ('hooks-' + name + '.log')
    with path.open('w') as log:
        process = subprocess.Popen(CLIENT + ['--log-level', 'debug'] + flags,
                                   stdout=subprocess.PIPE, stderr=log)
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
                    raise AssertionError('hook cleanup exceeded service stop-grace') from None
            process.stdout.close()


def test_scripts():
    with tempfile.TemporaryDirectory(prefix='svpn hook ') as temporary:
        directory = pathlib.Path(temporary)
        up = directory / 'up script'
        down = directory / 'down script'
        up.write_text('#!/bin/sh\n' + record(directory,
                      'printf HOOK-STDOUT; printf HOOK-STDERR >&2; '
                      'touch ' + quote(str(directory / 'up.done'))) + '\n')
        down.write_text('#!/bin/sh\n' + record(directory, 'true') + '\n')
        up.chmod(0o700)
        down.chmod(0o700)
        flags = ['--up-script', os.path.relpath(up), '--down-script', str(down)]
        args = CLIENT.copy()
        args[args.index('--tun-name') + 1] = ''
        path = LOG_DIR / 'hooks-scripts.log'
        with path.open('w') as log:
            process = subprocess.Popen(args + flags, stdout=subprocess.PIPE, stderr=log)
            try:
                until(lambda: (directory / 'up.done').exists())
                process.terminate()
                stdout, _ = process.communicate(timeout=15)
                assert process.returncode == 0, path.read_text()
                assert stdout == b'', stdout
                output = path.read_text()
                assert 'HOOK-STDOUT' in output and 'HOOK-STDERR' in output, output
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=25)
        name = verify_events(directory, ['up', 'down'], name=None)
        cleanup_verified(process, tun_name=name)
    print('PASS hooks scripts: relative path/spaces, kernel TUN name, env, stdout separation')


def test_up_barrier_and_routes():
    with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
        directory = pathlib.Path(temporary)
        extra_route = '192.0.2.123/32'
        up = record(directory,
                    'ip route replace "$SVPN_PEER_ADDR/32" dev "$SVPN_TUN_NAME" src "$SVPN_TUN_ADDR"; '
                    'ip route replace ' + extra_route + ' dev "$SVPN_TUN_NAME"; '
                    'touch ' + quote(str(directory / 'up.begin')) + '; sleep 7; '
                    'touch ' + quote(str(directory / 'up.done')))
        down = record(directory,
                      'ip route del ' + extra_route + ' dev "$SVPN_TUN_NAME"; '
                      'ip route del "$SVPN_PEER_ADDR/32" dev "$SVPN_TUN_NAME"')
        args = CLIENT + ['--mimic', 'mosh', '--up-command', up, '--down-command', down]
        with session('hooks-barrier', args=args, client_route=False,
                     ready_by_tun=True) as (process, path):
            until(lambda: (directory / 'up.begin').exists())
            assert extra_route.split('/')[0] in command(['ip', 'route', 'show', extra_route]).stdout
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.4)
                sock.sendto(b'before-up', (PEER, 9000))
                try:
                    sock.recv(128)
                    raise AssertionError('TUN served traffic before up completed')
                except socket.timeout:
                    pass
                assert 'vpn: started' not in path.read_text()
                until(lambda: (directory / 'up.done').exists(), seconds=9)
                until(lambda: 'vpn: started' in path.read_text())
                assert path.read_text().count('heartbeat received') >= 2, path.read_text()
                assert process.poll() is None, path.read_text()
                sock.settimeout(5)
                assert sock.recv(128) == b'before-up'
            tcp_echo(31)
        assert process.returncode == 0, path.read_text()
        verify_events(directory, ['up', 'down'])
        assert not command(['ip', 'route', 'show', extra_route]).stdout.strip()
        cleanup_verified(process)
    print('PASS hooks barrier: no early data, live heartbeats, hook-owned routes and TCP/UDP')


def test_up_failures():
    for name in ['exit', 'signal', 'spawn', 'timeout']:
        with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
            directory = pathlib.Path(temporary)
            body = {'exit': 'exit 7', 'signal': 'kill -TERM $$',
                    'timeout': 'sleep 60 & echo $! > ' + quote(str(directory / 'child.pid')) + '; wait'}
            if name == 'spawn':
                script = directory / 'bad interpreter'
                script.write_text('#!/no/such/hook/interpreter\n')
                script.chmod(0o700)
                flags = ['--up-script', str(script)]
            else:
                flags = ['--up-command', record(directory, body[name])]
            flags += ['--down-command', record(directory, 'true')]
            with client('up-' + name, flags) as (process, path):
                process.wait(timeout=25)
                assert process.returncode != 0, path.read_text()
                assert 'vpn: started' not in path.read_text(), path.read_text()
                assert 'hook up:' in path.read_text(), path.read_text()
                verify_events(directory, ['down'] if name == 'spawn' else ['up', 'down'])
                if name == 'timeout':
                    pid = (directory / 'child.pid').read_text().strip()
                    until(lambda: not pathlib.Path('/proc/' + pid).exists())
            cleanup_verified(process)
    print('PASS hooks failed up: exit/signal/spawn/timeout, compensation down, descendants reaped')


def test_signals_during_up():
    for stop in [signal.SIGINT, signal.SIGTERM]:
        with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
            directory = pathlib.Path(temporary)
            up = record(directory, 'sleep 60 & echo $! > '
                        + quote(str(directory / 'child.pid')) + '; wait')
            down = record(directory, 'sleep 0.3; touch ' + quote(str(directory / 'down.done')))
            with client('signal-' + str(stop), ['--up-command', up, '--down-command', down]) as (process, path):
                until(lambda: (directory / 'child.pid').exists())
                process.send_signal(stop)
                until(lambda: (directory / 'events').read_text().count('down|') == 1)
                assert pathlib.Path('/sys/class/net/svpn0').exists()
                process.send_signal(stop)
                process.wait(timeout=15)
                assert process.returncode == 0, path.read_text()
                assert (directory / 'down.done').exists()
                assert 'vpn: started' not in path.read_text(), path.read_text()
                verify_events(directory, ['up', 'down'])
                pid = (directory / 'child.pid').read_text().strip()
                until(lambda: not pathlib.Path('/proc/' + pid).exists())
            cleanup_verified(process)
    print('PASS hooks signals: cancel/reap up, TUN alive during down, repeat signals keep cleanup')


def test_failed_down_and_partial_up():
    with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
        directory = pathlib.Path(temporary)
        route = '192.0.2.124/32'
        up = record(directory, 'ip route replace ' + route + ' dev "$SVPN_TUN_NAME"; exit 7')
        down = record(directory, 'ip route del ' + route + ' dev "$SVPN_TUN_NAME"; exit 9')
        with client('partial-up', ['--up-command', up, '--down-command', down]) as (process, path):
            process.wait(timeout=20)
            output = path.read_text()
            assert process.returncode != 0, output
            assert 'cleanup failed' in output and 'hook down:' in output, output
            assert 'hook up:' in output.splitlines()[-1], output
            verify_events(directory, ['up', 'down'])
            assert not command(['ip', 'route', 'show', route]).stdout.strip()
        cleanup_verified(process)

    for name in ['signal', 'spawn', 'timeout']:
        with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
            directory = pathlib.Path(temporary)
            if name == 'spawn':
                script = directory / 'bad interpreter'
                script.write_text('#!/no/such/hook/interpreter\n')
                script.chmod(0o700)
                flags = ['--down-script', str(script)]
            else:
                body = ('kill -TERM $$' if name == 'signal' else
                        'sleep 60 & echo $! > ' + quote(str(directory / 'child.pid')) + '; wait')
                flags = ['--down-command', record(directory, body)]
            # Down also works without a configured up hook.
            with client('down-' + name, flags) as (process, path):
                until(lambda: 'vpn: started' in path.read_text())
                process.terminate()
                if name == 'timeout':
                    until(lambda: (directory / 'child.pid').exists())
                    assert pathlib.Path('/sys/class/net/svpn0').exists()
                process.wait(timeout=15)
                assert process.returncode != 0 and 'hook down:' in path.read_text(), path.read_text()
                if name == 'spawn':
                    assert not (directory / 'events').exists()
                    assert 'spawn failed' in path.read_text(), path.read_text()
                else:
                    verify_events(directory, ['down'])
                if name == 'timeout':
                    assert 'timed out' in path.read_text(), path.read_text()
                    pid = (directory / 'child.pid').read_text().strip()
                    until(lambda: not pathlib.Path('/proc/' + pid).exists())
            cleanup_verified(process)
    print('PASS hooks cleanup: partial up rollback, original error retained, down-only signal/spawn/timeout drops TUN')


def test_fatal_during_up():
    with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
        directory = pathlib.Path(temporary)
        up = record(directory, 'sleep 60 & echo $! > '
                    + quote(str(directory / 'child.pid')) + '; wait')
        with client('fatal', ['--up-command', up, '--down-command', record(directory, 'true')]) as (process, path):
            until(lambda: (directory / 'child.pid').exists())
            ssh('pkill -x svpn')
            # Exit must come from handling the SSH loss itself, not the 10 s hook deadline.
            process.wait(timeout=9)
            assert process.returncode != 0, path.read_text()
            assert 'hook up: timed out' not in path.read_text(), path.read_text()
            assert 'vpn: started' not in path.read_text(), path.read_text()
            verify_events(directory, ['up', 'down'])
            pid = (directory / 'child.pid').read_text().strip()
            until(lambda: not pathlib.Path('/proc/' + pid).exists())
        cleanup_verified(process)
    print('PASS hooks fatal: SSH loss cancels up and runs down before TUN cleanup')


def test_blocked_hook_output():
    with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
        directory = pathlib.Path(temporary)
        up = record(directory, 'yes HOOK-OUTPUT & echo $! > '
                    + quote(str(directory / 'child.pid')) + '; wait')
        args = CLIENT + ['--up-command', up, '--down-command', record(directory, 'true')]
        with session('hooks-blocked-output', args=args, blocked_logs=True) as (process, _path):
            process.wait(timeout=15)
            assert process.returncode != 0
            verify_events(directory, ['up', 'down'])
            pid = (directory / 'child.pid').read_text().strip()
            until(lambda: not pathlib.Path('/proc/' + pid).exists())
        cleanup_verified(process)
    print('PASS hooks blocked stderr: output backpressure cannot prevent timeout and cleanup')


def test_pool_transitions():
    with tempfile.TemporaryDirectory(prefix='svpn-hooks-') as temporary:
        directory = pathlib.Path(temporary)
        args = CLIENT_POOL + ['--mimic', 'mosh', '--up-command', record(directory, 'sleep 1'),
                              '--down-command', record(directory, 'true')]
        with session('hooks-pool', args=args, server_hosts=[SERVER, SERVER2], ready_timeout=20) as (process, path):
            until(lambda: 'serving (2/2 servers ready,' in path.read_text())
            verify_events(directory, ['up'])
            before = command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip()
            command(ssh_to(SERVER2) + ['iptables -w -I INPUT -p udp -j DROP'])
            try:
                until(lambda: f'ssh[{SERVER2}]: checking round failed' in path.read_text(), seconds=20)
                tcp_echo(32)
                verify_events(directory, ['up'])
            finally:
                command(ssh_to(SERVER2) + ['iptables -w -D INPUT -p udp -j DROP'])
            until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 2, seconds=30)
            assert command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip() == before
            command(ssh_to(SERVER2) + ['pkill -x svpn'])
            until(lambda: path.read_text().count('serving (2/2 servers ready,') >= 3, seconds=30)
            assert command(ssh_to(SERVER2) + ['pgrep -x svpn']).stdout.strip() != before
            assert process.poll() is None, path.read_text()
            tcp_echo(33)
            verify_events(directory, ['up'])
        verify_events(directory, ['up', 'down'])
        cleanup_verified(process, server_hosts=[SERVER, SERVER2])
    print('PASS hooks pool: one TUN up/down across second Ready, Checking, recovery and SSH retry')


def run():
    test_scripts()
    test_up_barrier_and_routes()
    test_up_failures()
    test_signals_during_up()
    test_failed_down_and_partial_up()
    test_fatal_during_up()
    test_blocked_hook_output()
    test_pool_transitions()


if __name__ == '__main__':
    run()
