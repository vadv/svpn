"""CLI/TOML parity in Linux containers; no host network changes."""
import json
import os
import pathlib
import shlex
import socket
import tempfile
import time

from _lib import SERVER, SERVER2, PEER, command, session, cleanup_verified, tcp_echo, until, ssh_to


def traffic(index):
    tcp_echo(index)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        payload = b'TOML UDP test'
        sock.sendto(payload, (PEER, 9000))
        received, address = sock.recvfrom(2048)
        assert received == payload and address == (PEER, 9000)
    command(['ping', '-n', '-c', '2', '-W', '2', PEER])


def test_configuration():
    with tempfile.TemporaryDirectory(prefix='svpn config ') as directory:
        base = pathlib.Path(directory)
        (base / 'identity').symlink_to('/keys/client')
        events = base / 'events'
        for event in ('up', 'down'):
            script = base / (event + ' hook')
            script.write_text('#!/bin/sh\nprintf ' + shlex.quote(event + ' %s\n')
                              + ' "$SVPN_TUN_NAME" >> ' + shlex.quote(str(events)) + '\n')
            script.chmod(0o700)
        common = ('ssh-user = "root"\nssh-identity = "identity"\n'
                  'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
                  'log-level = "debug"\nmimic = ["mosh"]\n')
        single = base / 'single.toml'
        single.write_text(common + f'server = "{SERVER}"\nstats-interval = 0\n'
                          'up-script = "up hook"\ndown-script = "down hook"\n')
        with session('config-single', args=['svpn', '--config', str(single)]) as (process, log):
            traffic(0)
            assert events.read_text() == 'up svpn0\n'
            time.sleep(2.1)
            assert 'stats: last ' not in log.read_text(), log.read_text()
        cleanup_verified(process)
        assert events.read_text() == 'up svpn0\ndown svpn0\n'
        print('PASS TOML single: relative identity/scripts, hooks, data, stats off, cleanup')

        events.unlink()
        multi = base / 'multi.toml'
        hooks = ''.join(event + '-command = ' + json.dumps(
            "printf '" + event + " %s\\n' \"$SVPN_TUN_NAME\" >> " + shlex.quote(str(events)))
            + '\n' for event in ('up', 'down'))
        multi.write_text(common + hooks + 'stats-interval = 1\n'
                         f'[[servers]]\naddress = "{SERVER}"\nweight = 2\n'
                         'udp-port-range = "61000-61009"\n'
                         f'[[servers]]\naddress = "{SERVER2}"\n'
                         'ssh-identity = "identity"\nudp-port-range = "62000-62009"\n')
        # Both config positions use the same grammar. This run covers prefix placement.
        with session('config-multi', args=['svpn', '--config', str(multi), 'multi'],
                     server_hosts=[SERVER, SERVER2], ready_timeout=20) as (process, log):
            until(lambda: 'serving (2/2 servers ready,' in log.read_text(), seconds=10)
            traffic(1)
            for host, low in [(SERVER, '61000'), (SERVER2, '62000')]:
                assert low in command(ssh_to(host) + ['pgrep -af "svpn serve"']).stdout
            until(lambda: 'stats: all servers' in log.read_text())
            assert events.read_text() == 'up svpn0\n'
        cleanup_verified(process, server_hosts=[SERVER, SERVER2])
        assert events.read_text() == 'up svpn0\ndown svpn0\n'
        print('PASS TOML multi: inherited/per-server identity, command hooks once, stats, cleanup')

        one = base / 'one.toml'
        one.write_text(common + f'stats-interval = 1\n[[servers]]\naddress = "{SERVER}"\n')
        with session('config-multi-one', args=['svpn', 'multi', '--config', str(one)]) as (process, log):
            traffic(2)
            until(lambda: 'stats: last ' in log.read_text())
        cleanup_verified(process)
        print('PASS TOML multi: one server accepted without special setup')

        bad = base / 'bad.toml'
        cases = [
            ([], common + f'server = "{SERVER}"\nunknown = true\n'),
            ([], common + f'server = "{SERVER}"\nweight = 1\n'),
            ([], common + f'server = "{SERVER}"\nup-script = ""\n'),
            ([], common + f'server = "{SERVER}"\nup-script = "up hook"\nup-command = "true"\n'),
            (['multi'], common + f'[[servers]]\naddress = "{SERVER}"\n'
             f'[[servers]]\naddress = "{SERVER2}"\npeer-tun-name = "bad/name"\n'),
        ]
        for mode, content in cases:
            bad.write_text(content)
            result = command(['svpn'] + mode + ['--config', str(bad)], check=False, timeout=3)
            assert result.returncode == 2, result.stdout
            assert not pathlib.Path('/sys/class/net/svpn0').exists(), result.stdout
        for args in [
            ['--config', str(single), '--mtu', '1280'],
            ['multi', '--config', str(multi), '--stats-interval', '30'],
            ['--config', str(single), '--up-command', 'true'],
            ['perf', '--config', str(single)],
            ['serve', '--config', str(single)],
            ['client', '--server', SERVER],
        ]:
            result = command(['svpn'] + args, check=False, timeout=3)
            assert result.returncode == 2, result.stdout
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(.2)
            marker = base / 'unexpected hook'
            bad.write_text(common + 'up-command = ' + json.dumps('touch ' + shlex.quote(str(marker)))
                           + '\n[[servers]]\naddress = "127.0.0.1"\n'
                           + f'ssh-port = {listener.getsockname()[1]}\n'
                           + f'[[servers]]\naddress = "{SERVER2}"\npeer-tun-name = "bad/name"\n')
            result = command(['svpn', 'multi', '--config', str(bad)], check=False, timeout=3)
            assert result.returncode == 2, result.stdout
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError('SSH started before the second server was validated')
            assert not marker.exists() and not pathlib.Path('/sys/class/net/svpn0').exists()
        result = command(['svpn', '--config', str(single)], check=False, timeout=3,
                         preexec_fn=lambda: os.setuid(65534))
        assert result.returncode == 2 and 'Permission denied' in result.stdout, result.stdout
        print('PASS TOML rejects mixed sources, invalid fields/hooks, unreadable file and removed client command before TUN')
