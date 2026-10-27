#!/usr/bin/env python3
"""Package a built binary; this does not build, deploy, or publish it."""

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOTICES = ROOT / "THIRD-PARTY-NOTICES"
TARGETS = {
    "linux-x86_64-gnu": ("x86_64-unknown-linux-gnu", "glibc, dynamically linked"),
    "openwrt-aarch64": ("aarch64-unknown-linux-musl", "musl, statically linked"),
    "macos-arm64": ("aarch64-apple-darwin", "libSystem"),
}
HOOKS = (
    "client-hooks/client-up",
    "client-hooks/client-down",
    "scripts/server-up",
    "scripts/server-down",
)


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, env=dict(os.environ, LC_ALL="C")).strip()


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


def pack(binary, target, output):
    binary = binary.resolve(strict=True)
    if not binary.is_file():
        raise ValueError("binary must be a regular file")
    before = binary.stat()
    description = command("file", "--brief", str(binary))
    if target == "linux-x86_64-gnu":
        valid = all(
            text in description for text in ("ELF 64-bit LSB", "x86-64", "/lib64/ld-linux-x86-64.so.2")
        )
    elif target == "openwrt-aarch64":
        valid = (
            "ELF 64-bit LSB" in description
            and "ARM aarch64" in description
            and any(text in description for text in ("statically linked", "static-pie linked"))
        )
    else:
        valid = description.startswith("Mach-O 64-bit executable arm64")
    if not valid:
        raise ValueError(f"binary does not match {target}: {description}")

    metadata = json.loads(
        command("cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1")
    )
    package = next(item for item in metadata["packages"] if item["name"] == "svpn")
    commit = command("git", "rev-parse", "HEAD")
    epoch = int(command("git", "show", "-s", "--format=%ct", "HEAD"))
    dirty = bool(command("git", "status", "--porcelain", "--untracked-files=normal"))
    info = {
        "name": "svpn",
        "version": package["version"],
        "commit": commit,
        "source_dirty": dirty,
        "source_date_epoch": epoch,
        "platform": target,
        "rust_target": TARGETS[target][0],
        "libc": TARGETS[target][1],
        "cpu_requirement": "hardware AES",
        "binary_sha256": digest(binary),
        "license": package.get("license"),
        "ci_run_id": os.environ.get("GITHUB_RUN_ID"),
    }
    encoded = (json.dumps(info, indent=2, sort_keys=True) + "\n").encode()
    notices = NOTICES.read_bytes()
    if not notices.strip():
        raise ValueError("dependency notices must not be empty")
    if not notices.startswith(f"Cargo.lock sha256: {digest(ROOT / 'Cargo.lock')}\n".encode()):
        raise ValueError("dependency notices do not match Cargo.lock; refresh them before packaging")
    documents = [
        ("build-info.json", encoded),
        ("LICENSE", (ROOT / "LICENSE").read_bytes()),
        ("THIRD-PARTY-NOTICES", notices),
    ]
    name = f"svpn-{package['version']}-{target}"
    if dirty:
        name += "-dirty"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + ".tar.gz")
    checksum = output / (archive.name + ".sha256")
    if archive.exists() or checksum.exists():
        raise FileExistsError(f"output already exists: {archive}")
    # Stable member order, timestamps and ownership; never package symlinks or setuid bits.
    created = []
    try:
        with archive.open("xb") as destination:
            created.append(archive)
            with gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=epoch) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
                    member = tarfile.TarInfo("svpn")
                    member.size = binary.stat().st_size
                    member.mode = 0o755
                    member.mtime = epoch
                    with binary.open("rb") as source:
                        tar.addfile(member, source)
                    for filename, content in documents:
                        member = tarfile.TarInfo(filename)
                        member.size = len(content)
                        member.mode = 0o644
                        member.mtime = epoch
                        tar.addfile(member, io.BytesIO(content))
                    for filename in HOOKS:
                        content = (ROOT / filename).read_bytes()
                        member = tarfile.TarInfo(filename)
                        member.size = len(content)
                        member.mode = 0o755
                        member.mtime = epoch
                        tar.addfile(member, io.BytesIO(content))
        after = binary.stat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("binary changed while packaging; wait for the build to finish")
        with checksum.open("x") as destination:
            created.append(checksum)
            destination.write(f"{digest(archive)}  {archive.name}\n")
    except BaseException:
        for path in reversed(created):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                print(f"package: failed to remove partial output {path}: {error}", file=sys.stderr)
        raise
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "dist/archives")
    args = parser.parse_args()
    try:
        archive = pack(args.binary, args.target, args.output)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"package: {error}\n")
    print(archive)


if __name__ == "__main__":
    main()
