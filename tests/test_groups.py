"""Check group coverage, ordering and dispatch without Docker or network access."""
import collections
import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import integration
import matrix
from test_artifacts import check


# Independent snapshot of the pre-split runner: keep every case and its order.
BASELINE = '''
test_lifecycle_hooks test_configuration test_authentication test_known_hosts_tofu
test_agent_identity test_no_ssh_binary test_custom_tun_name test_kernel_tun_name
test_log_levels test_client_stats test_secondary_server_address test_hostname_servers
test_pool_two_servers test_pool_udp_ports test_pool_failover test_pool_backoff
test_pool_all_down test_data test_client_rst_delivery test_idle_tcp_teardown
test_low_fd_limit test_ssh_loss test_heartbeat_loss test_blocked_stderr
test_server_blocked_stderr test_sigkill_takeover test_masquerade test_udp_port_range
test_tcp_transport test_tcp_ephemeral test_tcp_udp_blocked test_tcp_teardown
test_tcp_l0_l1 test_tcp_camouflage_ssh test_auto_tcp_fallback test_auto_exhausted
test_readiness_requires_kernel_reply test_checking_recovers_without_ssh_restart
test_checking_preserves_active_tcp_flows test_perf
'''.split()
MATRIX_BASELINE = (
    ('mosh', ('--mimic', 'mosh')),
    ('obfs', ('--mimic', 'obfs')),
    ('quic', ('--mimic', 'quic')),
    ('webrtc', ('--mimic', 'webrtc')),
    ('tcp-none', ('--mimic', 'none', '--tcp-port', '4190')),
    ('tcp-banner', ('--mimic', 'ssh', '--tcp-port', '4191')),
    ('tcp-ssh', ('--mimic', 'ssh', '--tcp-port', '4192')),
    ('auto', ('--tcp-port', '4193')),
)


def integration_groups():
    originals = {name: getattr(integration, name) for name in BASELINE}
    tests = [test for _, test in integration.TESTS]
    assert tests == list(originals.values()), 'all must preserve the original runner order'
    discovered = {test for name, test in vars(integration).items()
                  if name.startswith('test_') and callable(test)}
    assert set(tests) == discovered, 'every test must be assigned'
    assert len(tests) == len(set(tests)), 'a test is assigned twice'
    assert collections.Counter(owner for owner, _ in integration.TESTS) == {
        'bootstrap': 11, 'lifecycle-pool': 14, 'udp': 5, 'tcp-auto': 10,
    }
    for group in ('all', *integration.GROUPS):
        expected = [test for owner, test in integration.TESTS if group in ('all', owner)]
        for args in (['--group', group], []):
            called = []
            stubs = {test: (lambda test=test: called.append(test)) for test in tests}
            registry = [(owner, stubs[test]) for owner, test in integration.TESTS]
            with (patch.multiple(integration, **{name: stubs[test] for name, test in originals.items()}),
                  patch.object(integration, 'TESTS', registry),
                  patch.object(integration, 'scrub_firewall'),
                  patch.object(integration, 'command', return_value=SimpleNamespace(returncode=1)),
                  patch.object(sys, 'argv', ['integration.py', *args]),
                  patch.dict(os.environ, {'SVPN_TEST_GROUP': group}),
                  contextlib.redirect_stdout(io.StringIO())):
                integration.main()
            assert called == expected, (group, args)
    print('PASS integration: 40 cases assigned once, CLI/env selection and original order')


def matrix_groups():
    assert tuple((name, tuple(args)) for name, args in matrix.CONFIGS) == MATRIX_BASELINE
    assigned = [name for names in matrix.GROUPS.values() for name in names]
    assert collections.Counter(assigned) == collections.Counter(name for name, _ in MATRIX_BASELINE)
    for group in ('all', *matrix.GROUPS):
        called = []
        expected = [(name, args) for name, args in MATRIX_BASELINE
                    if group == 'all' or name in matrix.GROUPS[group]]
        with (patch.object(matrix, 'command', return_value=SimpleNamespace(returncode=1)),
              patch.object(matrix, 'run_config',
                           side_effect=lambda name, args: called.append((name, tuple(args))) or {}),
              patch.object(matrix.time, 'sleep'),
              patch.object(sys, 'argv', ['matrix.py', '--group', group]),
              contextlib.redirect_stdout(io.StringIO())):
            matrix.main()
        assert called == expected, group
    print('PASS matrix: 8 rows assigned once, original order and dispatch')


def matrix_diagnostics():
    for stalled, failure in [(False, False), (True, False), (True, True)]:
        stop = Mock()
        stop.wait.side_effect = [False, True] if stalled else [True]
        output = io.StringIO()
        results = [subprocess.TimeoutExpired('ss', 5) if failure else SimpleNamespace(stdout='client sockets'),
                   SimpleNamespace(stdout='server sockets')]
        with (patch.object(matrix, 'command', side_effect=results) as command,
              contextlib.redirect_stdout(output)):
            matrix.tcp_diagnostics(stop)
        assert command.call_count == (2 if stalled else 0)
        if stalled:
            assert 'TCP-DIAGNOSTICS client' in output.getvalue()
            assert 'server sockets' in output.getvalue()
            assert all(call.kwargs == {'check': False, 'timeout': 5}
                       for call in command.call_args_list)
            for call in command.call_args_list:
                script = call.args[0][-1]
                assert 'uname -r; ss -tinm; nstat -az' in script
                assert "timeout 2 tcpdump -i svpn0 -nn -S -tt -s 96 -c 20 'tcp port 9000'" in script
                assert '-A' not in script and '-X' not in script
        else:
            assert not output.getvalue()
    print('PASS matrix diagnostics: silent fast path, both peers, bounded failures')


def invalid_groups():
    for module, args in [(integration, ['--group', 'unknown']), (integration, []),
                         (matrix, ['--group', 'bootstrap']), (matrix, ['--unknown'])]:
        with (patch.object(module, 'command', return_value=SimpleNamespace(returncode=1)) as command,
              patch.object(integration, 'TESTS', []),
              patch.object(integration, 'scrub_firewall'),
              patch.object(matrix, 'run_config', side_effect=AssertionError('unexpected matrix run')),
              patch.object(sys, 'argv', [module.__file__, *args]),
              patch.dict(os.environ, {'SVPN_TEST_GROUP': 'unknown'}),
              contextlib.redirect_stderr(io.StringIO())):
            try:
                module.main()
            except SystemExit as error:
                assert error.code == 2
            else:
                raise AssertionError('invalid group accepted')
            command.assert_not_called()
    print('PASS invalid Python selectors fail before network setup')


def shell_groups():
    for group in ('all', *integration.GROUPS):
        calls = check('success', 0, (group,))
        assert all(line.endswith('group=' + group) for line in calls.splitlines())
        assert '/tests/matrix.py' not in calls
    for group in ('all', *matrix.GROUPS):
        calls = check('success', 0, ('--matrix', group))
        assert 'python3 -u /tests/matrix.py --group ' + group in calls
        assert all(line.endswith('group=' + group) for line in calls.splitlines())
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        (root / 'tests').mkdir()
        (root / 'bin').mkdir()
        script = root / 'tests/run.sh'
        shutil.copy2(pathlib.Path(__file__).with_name('run.sh'), script)
        docker = root / 'bin/docker'
        docker.write_text('#!/bin/sh\necho unexpected Docker invocation >&2\nexit 99\n')
        docker.chmod(0o755)
        env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
        for args, status in [(('--help',), 0), (('unknown',), 2), (('udp', 'extra'), 2),
                             (('--matrix', 'bootstrap'), 2), (('',), 2)]:
            result = subprocess.run(['bash', str(script), *args], env=env,
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == status, (args, result.stdout, result.stderr)
            assert not (root / 'tests/.work').exists(), 'selector must fail before side effects'
    print('PASS shell selection, matrix routing and fail-fast validation')


if __name__ == '__main__':
    integration_groups()
    matrix_groups()
    matrix_diagnostics()
    invalid_groups()
    shell_groups()
