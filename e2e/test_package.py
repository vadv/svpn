"""Check archive contents and labels with fake binaries; never execute a binary."""

import errno
import hashlib
import io
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
from contextlib import contextmanager, redirect_stderr
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "build"))
import package
import release

DESCRIPTIONS = {
    "linux-x86_64-gnu": "ELF 64-bit LSB pie executable, x86-64, interpreter /lib64/ld-linux-x86-64.so.2",
    "openwrt-aarch64": "ELF 64-bit LSB executable, ARM aarch64, statically linked",
    "macos-arm64": "Mach-O 64-bit executable arm64",
}


def check_failure_cleanup(binary, payload, root):
    original_open = pathlib.Path.open
    failures = []
    for failure in (
        "archive-close",
        "source-removed",
        "checksum-open",
        "checksum-write",
        "checksum-close",
        "archive-conflict",
        "checksum-conflict",
    ):
        binary.write_bytes(payload)
        output = root / failure
        foreign = []

        @contextmanager
        def failing_open(path, mode="r", *args, failure=failure, foreign=foreign, **kwargs):
            archive = mode == "xb"
            checksum = mode == "x"
            if (archive and failure == "archive-conflict") or (checksum and failure == "checksum-conflict"):
                with original_open(path, "wb") as destination:
                    destination.write(b"foreign output\n")
                foreign.append(path)
            if checksum and failure == "checksum-open":
                raise OSError(errno.ENOSPC, "injected checksum open failure")
            with original_open(path, mode, *args, **kwargs) as destination:
                if checksum and failure == "checksum-write":
                    with patch.object(
                        destination,
                        "write",
                        side_effect=OSError(errno.ENOSPC, "injected checksum write failure"),
                    ):
                        yield destination
                else:
                    yield destination
            if archive and failure == "source-removed":
                binary.unlink()
            if (archive and failure == "archive-close") or (checksum and failure == "checksum-close"):
                raise OSError(errno.ENOSPC, "injected output close failure")

        with patch.object(pathlib.Path, "open", new=failing_open):
            try:
                package.pack(binary, "linux-x86_64-gnu", output)
            except OSError as error:
                expected = (
                    errno.ENOENT
                    if failure == "source-removed"
                    else errno.EEXIST
                    if failure.endswith("-conflict")
                    else errno.ENOSPC
                )
                assert error.errno == expected, (failure, error)
            else:
                raise AssertionError(f"{failure}: packaging unexpectedly succeeded")
        remaining = list(output.iterdir())
        if remaining != foreign:
            failures.append(f"{failure}: own partial output remains: {[p.name for p in remaining]}")
        for path in foreign:
            assert path.read_bytes() == b"foreign output\n", "do not delete or modify another writer's output"
    assert not failures, "\n".join(failures)
    print("PASS rollback after archive/checksum failures and missing source; concurrent outputs preserved")


def check_cleanup_failures(binary, root):
    original_open = pathlib.Path.open
    original_unlink = pathlib.Path.unlink
    for failure in ("checksum", "archive", "both"):
        output = root / ("unlink-" + failure)
        attempted = []
        refused = []
        errors = io.StringIO()

        @contextmanager
        def failing_open(path, mode="r", *args, **kwargs):
            with original_open(path, mode, *args, **kwargs) as destination:
                yield destination
            if mode == "x":
                raise OSError(errno.ENOSPC, "injected primary checksum close failure")

        def failing_unlink(
            path, *args, output=output, attempted=attempted, failure=failure, refused=refused, **kwargs
        ):
            if path.parent == output:
                attempted.append(path)
                kind = "checksum" if path.suffix == ".sha256" else "archive"
                if failure in (kind, "both"):
                    refused.append(path)
                    raise PermissionError(errno.EACCES, "injected cleanup failure", str(path))
            return original_unlink(path, *args, **kwargs)

        with (
            patch.object(pathlib.Path, "open", new=failing_open),
            patch.object(pathlib.Path, "unlink", new=failing_unlink),
            patch.object(
                sys, "argv", ["package.py", "linux-x86_64-gnu", str(binary), "--output", str(output)]
            ),
            redirect_stderr(errors),
        ):
            try:
                package.main()
            except SystemExit as error:
                assert error.code == 1
            else:
                raise AssertionError("failed cleanup must not report success")
        assert len(attempted) == 2, "attempt every owned output even after unlink fails"
        assert set(output.iterdir()) == set(refused), "leave only outputs whose unlink failed"
        message = errors.getvalue()
        assert "injected primary checksum close failure" in message, message
        assert message.count("injected cleanup failure") == len(refused), message
        assert all(str(path) in message for path in refused), message
    print("PASS cleanup attempts all owned files and CLI reports primary and deletion errors")


def check_release(root):
    directory = root / "release"
    directory.mkdir()
    for target in package.TARGETS:
        for path in (root / target).iterdir():
            shutil.copyfile(path, directory / path.name)
    args = (directory, "v0.3.0", "a" * 40, "12345", "0.3.0")
    assert len(release.validate(*args)) == 6

    def rejected(arguments=args):
        try:
            release.validate(*arguments)
        except ValueError:
            return
        raise AssertionError("invalid release was accepted")

    rejected((directory, "v9.9.9", *args[2:]))
    rejected((directory, args[1], "b" * 40, *args[3:]))
    rejected((*args[:3], "other-run", args[4]))
    archive = next(directory.glob("*.tar.gz"))
    checksum = archive.with_name(archive.name + ".sha256")
    original, original_checksum = archive.read_bytes(), checksum.read_bytes()
    checksum.write_text("incorrect checksum\n")
    rejected()
    checksum.write_bytes(original_checksum)
    checksum.unlink()
    rejected()
    checksum.write_bytes(original_checksum)
    extra = directory / "unexpected.txt"
    extra.write_text("unexpected output")
    rejected()
    extra.unlink()

    with tarfile.open(archive) as tar:
        members = [(member, tar.extractfile(member).read()) for member in tar]
    for key, value in [
        ("source_dirty", True),
        ("commit", "b" * 40),
        ("ci_run_id", "different-run"),
        ("license", None),
        ("version", "9.9.9"),
        ("platform", "wrong"),
        ("binary_sha256", "0" * 64),
    ]:
        with tarfile.open(archive, "w:gz") as tar:
            for member, content in members:
                if member.name == "build-info.json":
                    info = json.loads(content)
                    info[key] = value
                    content = json.dumps(info).encode()
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        checksum.write_text(f"{package.digest(archive)}  {archive.name}\n")
        rejected()
    for defect in (
        "extra-member",
        "bad-mode",
        "empty-notices",
        "wrong-notices",
        "wrong-license",
        "changed-binary",
        "bad-hook",
    ):
        with tarfile.open(archive, "w:gz") as tar:
            for original_member, original_content in members:
                member = tarfile.TarInfo(original_member.name)
                member.mode = original_member.mode
                content = original_content
                if member.name == "svpn" and defect == "bad-mode":
                    member.mode = 0o4755
                if member.name == "svpn" and defect == "changed-binary":
                    content += b"changed"
                if member.name == "client-hooks/client-up" and defect == "bad-hook":
                    content = b"wrong hook"
                if member.name == "LICENSE" and defect == "wrong-license":
                    content = b"wrong license"
                if member.name == "THIRD-PARTY-NOTICES" and defect == "empty-notices":
                    content = b""
                if member.name == "THIRD-PARTY-NOTICES" and defect == "wrong-notices":
                    content = b"x" * len(content)
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
            if defect == "extra-member":
                tar.addfile(tarfile.TarInfo("../unexpected"))
        checksum.write_text(f"{package.digest(archive)}  {archive.name}\n")
        rejected()
    archive.write_bytes(original)
    checksum.write_bytes(original_checksum)
    assert len(release.validate(*args)) == 6
    print("PASS release gate: exact asset set, tag/version, clean commit/run provenance, license and hashes")


def check_current_notices():
    with package.NOTICES.open() as notices:
        header = notices.readline().rstrip("\n")
    expected = f"Cargo.lock sha256: {package.digest(package.ROOT / 'Cargo.lock')}"
    assert header == expected, "THIRD-PARTY-NOTICES is stale for the current Cargo.lock"
    print("PASS checked-in dependency notices match the current Cargo.lock")


def check():
    check_current_notices()
    with tempfile.TemporaryDirectory(prefix="svpn package ") as temporary:
        root = pathlib.Path(temporary)
        binary = root / "input binary"
        payload = b"fake binary bytes for archive checks\n"
        binary.write_bytes(payload)
        binary.chmod(0o4755)
        notices = root / "notices"
        notices.write_text(
            f"Cargo.lock sha256: {package.digest(package.ROOT / 'Cargo.lock')}\n"
            "Test dependency license notices\n"
        )
        link = root / "binary link"
        link.symlink_to(binary)
        replies = {
            ("file", "--brief", str(binary.resolve())): DESCRIPTIONS["linux-x86_64-gnu"],
            ("cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"): json.dumps(
                {"packages": [{"name": "svpn", "version": "0.3.0", "license": "MIT"}]}
            ),
            ("git", "rev-parse", "HEAD"): "a" * 40,
            ("git", "show", "-s", "--format=%ct", "HEAD"): "1600000000",
            ("git", "status", "--porcelain", "--untracked-files=normal"): "",
        }
        with (
            patch.object(package, "command", side_effect=lambda *args: replies[args]),
            patch.object(package, "NOTICES", notices),
            patch.object(release, "NOTICES", notices),
            patch.dict(os.environ, {"GITHUB_RUN_ID": "12345"}),
        ):
            for target, description in DESCRIPTIONS.items():
                replies[("file", "--brief", str(binary.resolve()))] = description
                archive = package.pack(link, target, root / target)
                repeated = package.pack(link, target, root / (target + "-again"))
                assert archive.read_bytes() == repeated.read_bytes(), "archive must be deterministic"
                checksum = archive.with_name(archive.name + ".sha256").read_text()
                assert checksum == (
                    hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
                )
                with tarfile.open(archive) as tar:
                    assert tar.getnames() == [
                        "svpn",
                        "build-info.json",
                        "LICENSE",
                        "THIRD-PARTY-NOTICES",
                        *package.HOOKS,
                    ]
                    assert tar.extractfile("LICENSE").read() == (package.ROOT / "LICENSE").read_bytes()
                    assert tar.extractfile("THIRD-PARTY-NOTICES").read() == notices.read_bytes()
                    assert all(member.isfile() and member.uid == member.gid == 0 for member in tar)
                    assert tar.getmember("svpn").mode == 0o755, "do not retain setuid bits"
                    assert tar.getmember("build-info.json").mode == 0o644
                    for filename in package.HOOKS:
                        assert tar.getmember(filename).mode == 0o755
                        assert tar.extractfile(filename).read() == (package.ROOT / filename).read_bytes()
                    assert all(member.mtime == 1600000000 for member in tar)
                    assert tar.extractfile("svpn").read() == payload
                    info = json.load(tar.extractfile("build-info.json"))
                assert info["binary_sha256"] == hashlib.sha256(payload).hexdigest()
                assert info["commit"] == "a" * 40 and info["ci_run_id"] == "12345"
                assert info["source_dirty"] is False and info["license"] == "MIT"
                assert archive.name == f"svpn-0.3.0-{target}.tar.gz"
                assert info["platform"] == target and info["rust_target"] == package.TARGETS[target][0]
                assert info["cpu_requirement"] == "hardware AES"
                before = archive.read_bytes()
                try:
                    package.pack(binary, target, archive.parent)
                except FileExistsError:
                    pass
                else:
                    raise AssertionError("existing archive was overwritten")
                assert archive.read_bytes() == before
            check_release(root)
            replies[("file", "--brief", str(binary.resolve()))] = (
                "ELF 64-bit LSB pie executable, ARM aarch64, static-pie linked"
            )
            package.pack(binary, "openwrt-aarch64", root / "static-pie")
            print(
                "PASS archive contents, three target labels, checksums, deterministic bytes, "
                "safe modes and no overwrite"
            )

            for target, description in [
                ("linux-x86_64-gnu", DESCRIPTIONS["macos-arm64"]),
                ("openwrt-aarch64", "ELF 64-bit LSB executable, ARM aarch64, dynamically linked"),
            ]:
                replies[("file", "--brief", str(binary.resolve()))] = description
                try:
                    package.pack(binary, target, root / "wrong-arch")
                except ValueError:
                    pass
                else:
                    raise AssertionError("wrong architecture/linkage accepted")
                assert not (root / "wrong-arch").exists()
            print("PASS wrong architecture and dynamic ARM linkage rejected before archive creation")

            replies[("file", "--brief", str(binary.resolve()))] = DESCRIPTIONS["linux-x86_64-gnu"]
            replies[("git", "status", "--porcelain", "--untracked-files=normal")] = " M src/main.rs"
            archive = package.pack(binary, "linux-x86_64-gnu", root / "dirty")
            assert "-dirty.tar.gz" in archive.name
            with tarfile.open(archive) as tar:
                assert json.load(tar.extractfile("build-info.json"))["source_dirty"] is True
            print("PASS dirty worktree explicitly labelled, never presented as the clean commit")

            original_digest = package.digest

            def changing_digest(path):
                result = original_digest(path)
                if path == binary.resolve():
                    binary.write_bytes(payload + b"changed")
                return result

            with patch.object(package, "digest", side_effect=changing_digest):
                try:
                    package.pack(binary, "linux-x86_64-gnu", root / "changed")
                except ValueError as error:
                    assert "binary changed" in str(error)
                else:
                    raise AssertionError("changing input accepted")
            assert not list((root / "changed").iterdir())
            print("PASS input mutation rejected and incomplete archive removed")
            check_failure_cleanup(binary, payload, root)
            check_cleanup_failures(binary, root)
            notices.write_text("Cargo.lock sha256: outdated\nOld notices\n")
            try:
                package.pack(binary, "linux-x86_64-gnu", root / "stale-notices")
            except ValueError as error:
                assert "Cargo.lock" in str(error)
            else:
                raise AssertionError("stale dependency notices accepted")
            assert not (root / "stale-notices").exists()
            notices.write_text("")
            try:
                package.pack(binary, "linux-x86_64-gnu", root / "empty-notices")
            except ValueError as error:
                assert "notices" in str(error)
            else:
                raise AssertionError("empty dependency notices accepted")
            assert not (root / "empty-notices").exists()
            notices.unlink()
            try:
                package.pack(binary, "linux-x86_64-gnu", root / "missing-notices")
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("missing dependency notices accepted")
            print("PASS stale, empty or missing dependency notices rejected before archive creation")


if __name__ == "__main__":
    check()
