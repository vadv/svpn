#!/usr/bin/env python3
"""Verify the complete release artifact set before uploading or publishing it."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile

from package import NOTICES, ROOT, TARGETS, command, digest


def validate(directory, tag, commit, run_id, version):
    if tag != 'v' + version:
        raise ValueError('tag must match the Cargo package version')
    files = sorted(path for path in directory.rglob('*') if path.is_file())
    expected_names = {
        f'svpn-{version}-{target}.tar.gz{suffix}'
        for target in TARGETS for suffix in ('', '.sha256')
    }
    if len(files) != len(expected_names) or {p.name for p in files} != expected_names:
        raise ValueError('expected exactly three platform archives and their checksums')
    notices = NOTICES.read_bytes()
    for archive in (path for path in files if path.name.endswith('.tar.gz')):
        target = archive.name[len(f'svpn-{version}-'):-len('.tar.gz')]
        checksum = archive.with_name(archive.name + '.sha256')
        if checksum.read_text() != f'{digest(archive)}  {archive.name}\n':
            raise ValueError(f'archive checksum mismatch: {archive.name}')
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            names = ['svpn', 'build-info.json', 'LICENSE', 'THIRD-PARTY-NOTICES']
            if ([m.name for m in members] != names or
                    not all(m.isfile() and m.uid == m.gid == 0 for m in members) or
                    [m.mode for m in members] != [0o755, 0o644, 0o644, 0o644]):
                raise ValueError(f'unexpected archive contents or permissions: {archive.name}')
            if tar.getmember('build-info.json').size > 65536:
                raise ValueError('oversized build metadata')
            info = json.load(tar.extractfile('build-info.json'))
            expected = {
                'name': 'svpn', 'version': version, 'commit': commit,
                'ci_run_id': run_id, 'platform': target,
                'rust_target': TARGETS[target][0], 'libc': TARGETS[target][1],
                'cpu_requirement': 'hardware AES', 'license': 'MIT',
            }
            if (not isinstance(info, dict) or info.get('source_dirty') is not False or
                    any(info.get(key) != value for key, value in expected.items())):
                raise ValueError(f'artifact provenance mismatch: {archive.name}')
            binary_hash = hashlib.sha256()
            with tar.extractfile('svpn') as binary:
                while chunk := binary.read(1024 * 1024):
                    binary_hash.update(chunk)
            if info.get('binary_sha256') != binary_hash.hexdigest():
                raise ValueError(f'binary checksum mismatch: {archive.name}')
            license_bytes = (ROOT / 'LICENSE').read_bytes()
            if (tar.getmember('LICENSE').size != len(license_bytes) or
                    tar.extractfile('LICENSE').read() != license_bytes or
                    not notices.strip() or
                    tar.getmember('THIRD-PARTY-NOTICES').size != len(notices) or
                    tar.extractfile('THIRD-PARTY-NOTICES').read() != notices):
                raise ValueError(f'missing license notices: {archive.name}')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('tag')
    parser.add_argument('commit')
    parser.add_argument('run_id')
    args = parser.parse_args()
    try:
        metadata = json.loads(command('cargo', 'metadata', '--offline', '--locked',
                                      '--no-deps', '--format-version', '1'))
        version = next(p['version'] for p in metadata['packages'] if p['name'] == 'svpn')
        for path in validate(args.directory, args.tag, args.commit, args.run_id, version):
            print(path)
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'release: {error}\n')


if __name__ == '__main__':
    main()
