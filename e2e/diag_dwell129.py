"""Close timing of flow 129: the FIN pair after an out-of-window RST must go
through the 15-second dwell, not close instantly."""
import re
import socket
import time

from integration import PEER, session, ssh


def forged_then_close():
    with session('dwell129') as (process, path):
        # A little preliminary traffic so there is at least one flow.
        for _ in range(2):
            with socket.create_connection((PEER, 9000), timeout=5) as stream:
                stream.sendall(b'pre')
                assert stream.recv(3, socket.MSG_WAITALL) == b'pre'
        log = path.read_text()
        base_ids = set(re.findall(r'flow_open role=client id=(\d+)', log))
        with socket.create_connection((PEER, 9000), timeout=5) as stream:
            stream.sendall(b'before')
            assert stream.recv(6, socket.MSG_WAITALL) == b'before'
            ssh(f'python3 /e2e/forged_rst.py {stream.getsockname()[1]}')
            time.sleep(2.2)
            stream.sendall(b'after')
            assert stream.recv(5, socket.MSG_WAITALL) == b'after'
        t_close = time.monotonic()
        log = path.read_text()
        target_ids = set(re.findall(r'flow_open role=client id=(\d+)', log)) - base_ids
        assert len(target_ids) == 1, target_ids
        target = target_ids.pop()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            text = path.read_text()
            for line in text.splitlines():
                if f'close_flow id={target}' in line:
                    rel = time.monotonic() - t_close
                    print(f'flow {target}: close {rel:.1f}s after FIN')
                    print(line.strip())
                    return
            time.sleep(1)
        print(f'flow {target}: did not close within 25s')
        raise SystemExit(1)


forged_then_close()
