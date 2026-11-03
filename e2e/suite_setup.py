"""Provision a fresh Debian SSH host without starting SVPN or changing its network."""

import base64
import pathlib
import subprocess
import tempfile
import time
from types import SimpleNamespace

from _lib import command, ssh_to

SERVER = "172.30.88.2"
SSH = ssh_to(SERVER)

# Builds fake release fixtures per scenario and selects the curl-shim mode.
FIXTURE_BUILDER = '''\
"""Build fake release fixtures for one installer scenario."""
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path("/fake")


def add_file(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755
    tar.addfile(info, io.BytesIO(data))


def build_asset(path, version, platform="linux-x86_64-gnu", meta=True, extra=(), symlink_binary=False):
    info = {
        "version": version,
        "platform": platform,
        "rust_target": "x86_64-unknown-linux-gnu",
        "libc": "glibc, dynamically linked",
        "cpu_requirement": "hardware AES",
        "license": "MIT",
    }
    if meta:
        info["control_version"] = 3
        info["server_hooks"] = 1
    with tarfile.open(path, "w:gz") as tar:
        if symlink_binary:
            link = tarfile.TarInfo("svpn")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            link.mode = 0o755
            tar.addfile(link)
        else:
            add_file(tar, "svpn", f"#!/bin/sh\\necho 'svpn {version}'\\n".encode())
        add_file(tar, "build-info.json", json.dumps(info, indent=2).encode())
        add_file(tar, "LICENSE", b"MIT")
        add_file(tar, "THIRD-PARTY-NOTICES", b"none")
        for name in extra:
            add_file(tar, name, b"x")


def write_pair(asset_name):
    digest = hashlib.sha256((ROOT / "asset").read_bytes()).hexdigest()
    (ROOT / "checksum").write_text(f"{digest}  {asset_name}\\n")


def write_release(tag):
    # The installer greps a line starting with "tag_name", like the real API renders it.
    (ROOT / "release.json").write_text('{\\n  "tag_name": "%s"\\n}\\n' % tag)


mode, client = sys.argv[1], sys.argv[2]
asset = f"svpn-{client}-linux-x86_64-gnu.tar.gz"
if mode == "good":
    build_asset(ROOT / "asset", client)
    write_pair(asset)
    write_release(f"v{client}")
elif mode == "fallback":
    build_asset(ROOT / "asset", "0.9.5")
    write_pair("svpn-0.9.5-linux-x86_64-gnu.tar.gz")
    write_release("v0.9.5")
elif mode == "incompatible":
    build_asset(ROOT / "asset", "0.9.5", meta=False)
    write_pair("svpn-0.9.5-linux-x86_64-gnu.tar.gz")
    write_release("v0.9.5")
elif mode == "bad-checksum":
    build_asset(ROOT / "asset", client)
    (ROOT / "checksum").write_text(f"{'0' * 64}  {asset}\\n")
elif mode == "evil-members":
    build_asset(ROOT / "asset", client, extra=("evil",))
    write_pair(asset)
elif mode == "symlink-member":
    build_asset(ROOT / "asset", client, symlink_binary=True)
    write_pair(asset)
elif mode == "wrong-platform":
    build_asset(ROOT / "asset", client, platform="linux-aarch64-gnu")
    write_pair(asset)
else:
    raise SystemExit(f"unknown mode {mode}")
(ROOT / "exact_tag").write_text(f"v{client}")
(ROOT / "mode").write_text(mode)
(ROOT / "curl.log").write_text("")
print(f"fixtures ready: {mode}")
'''

# Serves crafted fixtures instead of GitHub; the exact-tag pair can be made 404.
CURL_SHIM = """\
#!/bin/sh
url=
out=
prev=
for arg in "$@"; do
    [ "$prev" = "-o" ] && out=$arg
    case $arg in http*) url=$arg ;; esac
    prev=$arg
done
echo "$url" >>/fake/curl.log
case "$url" in
    */releases/latest) cat /fake/release.json >"$out"; exit 0 ;;
esac
mode=$(cat /fake/mode)
tag=$(cat /fake/exact_tag)
case "$mode:$url" in
    fallback:*"/download/$tag/"*|incompatible:*"/download/$tag/"*)
        echo "curl: (22) The requested URL returned error: 404" >&2
        exit 22
        ;;
esac
case "$url" in
    *.sha256) cat /fake/checksum >"$out" ;;
    *) cat /fake/asset >"$out" ;;
esac
"""


def remote(script, **kwargs):
    return command(SSH + [script], **kwargs)


def snapshot():
    return remote(
        "ip -4 -6 route show; cat /etc/resolv.conf; "
        "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding; "
        "iptables-save | sed -E '/^# (Generated|Completed)/d; s/\\[[0-9]+:[0-9]+\\]/[0:0]/g'; "
        "nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/g'"
    ).stdout


def assert_snapshot(before):
    after = snapshot()
    assert after == before, f"--- before ---\n{before}\n--- after ---\n{after}"


def plant_fakes():
    builder = base64.b64encode(FIXTURE_BUILDER.encode()).decode()
    shim = base64.b64encode(CURL_SHIM.encode()).decode()
    remote(
        f"mkdir -p /fake && echo {builder} | base64 -d > /fake/build.py"
        f" && echo {shim} | base64 -d > /usr/local/bin/curl && chmod 755 /usr/local/bin/curl"
    )


def fake_setup(config, mode, version):
    remote(f"python3 /fake/build.py {mode} {version}")
    return command(["svpn", "setup", "--config", str(config)], check=False, timeout=360)


def fake_scenarios(config):
    version = command(["svpn", "--version"]).stdout.split()[-1]
    plant_fakes()

    result = fake_setup(config, "fallback", version)
    assert "status=success version=0.9.5" in result.stdout, result.stdout
    assert "using latest stable" in result.stdout, result.stdout
    if version != "0.9.5":
        assert f"downgrade={version}->0.9.5" in result.stdout, result.stdout
    print("PASS setup fake: missing exact release falls back to a compatible stable one")

    result = fake_setup(config, "incompatible", version)
    assert "status=failed" in result.stdout, result.stdout
    assert "lacks compatible control/hook metadata" in result.stdout, result.stdout
    print("PASS setup fake: fallback rejects a release without hook metadata")

    result = fake_setup(config, "bad-checksum", version)
    assert "status=failed" in result.stdout, result.stdout
    assert "checksum or filename mismatch" in result.stdout, result.stdout
    assert "releases/latest" not in remote("cat /fake/curl.log").stdout
    print("PASS setup fake: checksum mismatch is an error, never a fallback")

    for mode, message in [
        ("evil-members", "unexpected release archive members"),
        ("symlink-member", "is not a regular file"),
        ("wrong-platform", "release metadata platform mismatch"),
    ]:
        result = fake_setup(config, mode, version)
        assert "status=failed" in result.stdout, result.stdout
        assert message in result.stdout, result.stdout
        print(f"PASS setup fake: {mode} archive is rejected")

    remote("rm -f /usr/local/bin/svpn && ln -s /bin/sh /usr/local/bin/svpn")
    result = fake_setup(config, "good", version)
    remote("rm -f /usr/local/bin/svpn")
    assert "status=failed" in result.stdout, result.stdout
    assert "must not be a symlink" in result.stdout, result.stdout
    print("PASS setup fake: symlinked destination is rejected by preflight")

    remote("printf '#!/bin/sh\\necho svpn 9.9.9\\n' > /usr/local/bin/svpn")
    remote("chmod 755 /usr/local/bin/svpn")
    result = fake_setup(config, "good", version)
    assert "status=success" in result.stdout, result.stdout
    assert f"downgrade=9.9.9->{version}" in result.stdout, result.stdout
    print("PASS setup fake: replacing a newer binary reports the downgrade")

    remote("printf '#!/bin/sh\\nexit 1\\n' > /usr/local/bin/stat && chmod 755 /usr/local/bin/stat")
    result = fake_setup(config, "good", version)
    remote("rm -f /usr/local/bin/stat")
    assert "status=partial" in result.stdout, result.stdout
    assert "changed=/usr/local/bin/svpn" in result.stdout, result.stdout
    result = fake_setup(config, "good", version)
    assert "status=success" in result.stdout, result.stdout
    print("PASS setup fake: interrupted verification reports partial and a re-run recovers")


def case_real_runs(ctx):
    original = pathlib.Path(ctx.config).read_bytes()
    for run in (1, 2):
        result = command(["svpn", "setup", "--config", ctx.config], timeout=300)
        assert "status=success" in result.stdout, result.stdout
        assert f"host={SERVER}" in result.stdout, result.stdout
        assert pathlib.Path(ctx.config).read_bytes() == original
        assert_snapshot(ctx.before)
        admin_after = remote("sha256sum /etc/svpn/admin.conf; stat -c %a /etc/svpn/admin.conf").stdout
        assert admin_after == ctx.admin_before
        assert remote("test ! -e /tmp/svpn-setup-hook-ran").returncode == 0
        assert remote("test ! -e /usr/local/lib/svpn").returncode == 0
        assert remote("! pgrep -f '^svpn serve'").returncode == 0
        assert (
            remote("test ! -e /etc/systemd/system/svpn.service && test ! -e /etc/init.d/svpn").returncode == 0
        )
        print(f"PASS setup run {run}: fresh/overwrite, no hooks, service or network changes")


def case_multi_isolation(ctx):
    multi = pathlib.Path(ctx.directory) / "multi.toml"
    multi.write_text(
        'ssh-user = "root"\nssh-identity = "/keys/client"\n'
        'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
        '[[servers]]\naddress = "172.30.88.250"\n'
        f'[[servers]]\naddress = "{SERVER}"\n'
    )
    result = command(["svpn", "setup", "--config", str(multi)], check=False, timeout=360)
    assert result.returncode != 0, result.stdout
    assert "host=172.30.88.250 port=22 status=failed" in result.stdout, result.stdout
    assert f"host={SERVER} port=22 status=success" in result.stdout, result.stdout
    assert_snapshot(ctx.before)
    print("PASS setup multi: host failure is isolated, later host still succeeds")
    ctx.multi = str(multi)


def case_cancellation(ctx):
    interrupted = subprocess.Popen(
        ["svpn", "setup", "--config", ctx.multi],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.5)
    interrupted.terminate()
    stdout, stderr = interrupted.communicate(timeout=10)
    assert interrupted.returncode != 0, (stdout, stderr)
    assert "status=not-attempted" in stdout, (stdout, stderr)
    print("PASS setup cancellation: SIGTERM fails and reports the skipped host")


def case_fake_installer(ctx):
    fake_scenarios(ctx.config)


# Ordered case registry pinned by e2e/test_groups.py.
CASES = (
    ("fresh-overwrite", case_real_runs),
    ("multi-isolation", case_multi_isolation),
    ("cancellation", case_cancellation),
    ("fake-installer", case_fake_installer),
)


def main():
    assert remote("test ! -e /usr/local/bin/svpn").returncode == 0
    remote("mkdir -p /etc/svpn; printf 'keep\\n' >/etc/svpn/admin.conf; chmod 640 /etc/svpn/admin.conf")
    before = snapshot()
    admin_before = remote("sha256sum /etc/svpn/admin.conf; stat -c %a /etc/svpn/admin.conf").stdout
    with tempfile.TemporaryDirectory(prefix="svpn-setup-e2e-") as directory:
        config = pathlib.Path(directory) / "client.toml"
        config.write_text(
            f'server = "{SERVER}"\nssh-user = "root"\nssh-identity = "/keys/client"\n'
            'peer-tun-name = "svpn0"\ntun-name = "svpn0"\n'
        )
        ctx = SimpleNamespace(
            config=str(config),
            directory=directory,
            before=before,
            admin_before=admin_before,
        )
        for _name, case in CASES:
            case(ctx)

    local_version = command(["svpn", "--version"]).stdout.split()[-1]
    assert remote("svpn --version").stdout.split()[-1] == local_version
    modes = remote("stat -c %a /usr/local/bin/svpn").stdout
    assert modes.split() == ["755"]
    hashes = remote("sha256sum /usr/local/bin/svpn").stdout
    assert len(hashes.splitlines()) == 1
    print("PASS setup artifacts:", hashes.replace("\n", "; "))
    print("SETUP COMPOSE TESTS PASSED", flush=True)


if __name__ == "__main__":
    main()
