"""Generate disposable SSH credentials for this isolated Compose run."""
import pathlib
import subprocess

root = pathlib.Path('/keys')
root.mkdir(exist_ok=True)
for name in ('host', 'client', 'wrong'):
    path = root / name
    if not path.exists():
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
public_host = (root / 'host.pub').read_text().split()
(root / 'known_hosts').write_text('172.30.77.2,172.30.77.4,172.30.77.5 ' + ' '.join(public_host[:2]) + '\n')
wrong_host = (root / 'wrong.pub').read_text().split()
(root / 'wrong_known_hosts').write_text('172.30.77.2 ' + ' '.join(wrong_host[:2]) + '\n')
print('Disposable keys ready; host key pinned.')
