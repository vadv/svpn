"""Check the Compose wrapper's exit/cleanup paths without Docker or network access."""
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time


DOCKER = '''#!/usr/bin/env python3
import os
import pathlib
import signal
import sys
import time

case = os.environ['ARTIFACT_CASE']
root = pathlib.Path.cwd()
assert sys.argv[1:3] == ['compose', '-f'], 'Compose file must be explicit'
assert pathlib.Path(sys.argv[3]).resolve() == root / 'compose.yaml'
assert sys.argv[4:6] == ['-p', 'svpn-test'], 'Compose project must be explicit'
command = sys.argv[6]
with (root / 'calls').open('a') as out:
    out.write(' '.join(['compose', *sys.argv[6:]]) + ' group=' + os.environ['SVPN_TEST_GROUP'] + '\\n')
print('docker ' + command, flush=True)
if command == 'build' and case == 'build-fails':
    sys.exit(23)
if command == 'up':
    assert not (root / 'resources').exists(), 'previous Compose state survived'
    (root / 'resources').touch()
    if case == 'startup-fails':
        sys.exit(29)
if command == 'run':
    logs = pathlib.Path(os.environ['SVPN_TEST_ARTIFACTS']) / 'sessions'
    (logs / 'flow.log').write_text('flow diagnostic\\n')
    (root / 'tests/.work/credential.key').write_text('PRIVATE TEST MATERIAL')
    if case == 'test-fails':
        sys.exit(17)
if command == 'run' and case.endswith('-running'):
    def stop(_signal, _frame):
        (root / 'forwarded').touch()
        sys.exit(143)
    signal.signal(signal.SIGTERM, stop)
    (root / 'ready').write_text(str(os.getpgrp()))
    time.sleep(30)
if command == 'logs' and case.endswith('-cleanup'):
    (root / 'ready').write_text(str(os.getpgrp()))
    time.sleep(0.3)
if command == 'down':
    if case == 'cleanup-fails' and (root / 'resources').exists():
        sys.exit(31)
    (root / 'resources').unlink(missing_ok=True)
'''


def check(case, status, args=()):
    with tempfile.TemporaryDirectory(prefix='svpn artifacts ') as temporary:
        root = pathlib.Path(temporary)
        (root / 'tests').mkdir()
        (root / 'bin').mkdir()
        shutil.copy2(pathlib.Path(__file__).with_name('run.sh'), root / 'tests/run.sh')
        docker = root / 'bin/docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        env = dict(os.environ, ARTIFACT_CASE=case,
                   COMPOSE_FILE=str(root / 'foreign-compose.yaml'),
                   COMPOSE_PROJECT_NAME='foreign-production-project',
                   PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
        if case == 'stale-state':
            (root / 'resources').touch()
        for attempt in range(2 if case == 'success' else 1):
            process = subprocess.Popen(['bash', str(root / 'tests/run.sh'), *args], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                if case.startswith(('term-', 'int-')):
                    deadline = time.monotonic() + 5
                    while not (root / 'ready').exists():
                        assert process.poll() is None, 'wrapper exited before signal test'
                        assert time.monotonic() < deadline, 'signal target did not start'
                        time.sleep(0.01)
                    # Signal only the wrapper PID, not its process group.
                    process.send_signal(signal.SIGINT if case.startswith('int-') else signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=10)
            finally:
                if process.poll() is None:
                    groups = {process.pid}
                    if (root / 'ready').exists():
                        groups.add(int((root / 'ready').read_text()))
                    for group in groups:
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.communicate(timeout=3)
            assert process.returncode == status, (case, stdout, stderr)
            outputs = list((root / 'tests/.work/artifacts').iterdir())
            assert len(outputs) == attempt + 1, 'each run needs a separate artifact directory'
            for output in outputs:
                assert (output / 'preflight.log').exists()
                assert (output / 'build.log').exists()
                assert (output / 'services.log').exists()
                assert 'docker logs' in (output / 'services.log').read_text()
                assert 'docker down' in (output / 'services.log').read_text()
                files = [p for p in output.rglob('*') if p.is_file()]
                assert all(p.suffix == '.log' for p in files), files
                assert all('PRIVATE TEST MATERIAL' not in p.read_text() for p in files)
                if case not in ('build-fails', 'startup-fails'):
                    assert (output / 'sessions/flow.log').read_text() == 'flow diagnostic\n'
                    assert 'docker run' in (output / 'runner.log').read_text()
            assert (root / 'resources').exists() == (case == 'cleanup-fails')
            calls = (root / 'calls').read_text()
            assert calls.splitlines()[0].startswith('compose down --volumes --remove-orphans')
            if case == 'cleanup-fails':
                assert 'Compose cleanup failed' in stderr
            if case.endswith('-running'):
                assert (root / 'forwarded').exists(), 'child did not receive termination'
    print('PASS artifact wrapper: ' + case)
    return calls


if __name__ == '__main__':
    for case, status in [('success', 0), ('stale-state', 0), ('test-fails', 17), ('build-fails', 23),
                         ('startup-fails', 29), ('cleanup-fails', 1),
                         ('term-running', 143), ('term-cleanup', 143),
                         ('int-running', 130), ('int-cleanup', 130)]:
        check(case, status)
