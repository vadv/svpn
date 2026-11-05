"""Jobs group: background database jobs — degraded start, live reload, run_if."""

import ipaddress
import pathlib

from _lib import SERVER, cleanup_verified, session, until

FILES = "172.30.77.8"
CSV = pathlib.Path("/tmp/e2e-jobs-asn.csv")
CONFIG = pathlib.Path("/tmp/e2e-jobs.hcl")
# One /17 block per row: 131072 rows clears Geo::load's 100k floor and gives
# every destination subnet a distinct ASN.
HOST_BITS = 15
ROWS = 1 << (32 - HOST_BITS)


def write_fixture(asn_base):
    lines = []
    for row in range(ROWS):
        start = row << HOST_BITS
        end = start | ((1 << HOST_BITS) - 1)
        a = ipaddress.IPv4Address(start)
        b = ipaddress.IPv4Address(end)
        lines.append(f'"{a}","{b}",{asn_base + row % 7}')
    pathlib.Path("/files/asn.csv").write_text("\n".join(lines) + "\n")


def jobs_config(url):
    CONFIG.write_text(
        'ssh {\n  user = "root"\n  identity = "/keys/client"\n}\n'
        'tunnel {\n  peer_name = "svpn0"\n  name = "svpn0"\n}\n'
        'log_level = "debug"\n'
        'transport {\n  stats = "1s"\n  mimic = ["mosh"]\n}\n'
        f'geo {{\n  db = "{CSV}"\n}}\n'
        'fallback_sticky {\n  strategy = "sticky-asn"\n}\n'
        f'server "s1" {{\n  address = "{SERVER}"\n}}\n'
        'job "update" {\n'
        '  every   = "5m"\n'
        '  timeout = "1m"\n'
        '  run_if  = "[ ! -f \\"$SVPN_GEO_DB\\" ]"\n'
        '  run     = "python3 -c '
        "'import sys, urllib.request; "
        "urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "
        f'{url} \\"$SVPN_GEO_DB\\""\n'
        '  reload  = ["geo"]\n'
        "}\n"
    )
    return ["svpn", "multi", "--config", str(CONFIG)]


def test_missing_database_degrades_then_reloads_live():
    """Fresh machine: start degraded, the job fetches, sticky-asn goes live."""
    CSV.unlink(missing_ok=True)
    write_fixture(64512)
    with session("jobs-bootstrap", args=jobs_config(f"http://{FILES}/asn.csv")) as (process, path):
        until(lambda: "vpn: degraded start" in path.read_text(), seconds=15)
        assert "job update fetching it" in path.read_text()
        # A fast job reloads before the first periodic report, so the
        # "geo: missing" honesty line is transient here; the failure test
        # below pins it where the state persists.
        until(
            lambda: "geo database reloaded (job update): 131072 IPv4 ranges" in path.read_text(), seconds=30
        )
        # The reload activated the policy live: the sticky report requires geo.
        until(lambda: "sticky: lookup hit" in path.read_text(), seconds=15)
        assert "geo: missing" not in path.read_text().splitlines()[-1]
    cleanup_verified(process)
    print("PASS jobs bootstrap: degraded start, background fetch, live sticky-asn")


def test_run_if_skips_when_the_database_is_fresh():
    """Second start with the database in place: the gate cheaply skips."""
    assert CSV.exists(), "the first test must have installed the database"
    with session("jobs-fresh", args=jobs_config(f"http://{FILES}/asn.csv")) as (process, path):
        until(lambda: "vpn: started" in path.read_text(), seconds=15)
        until(lambda: "job: update up-to-date, skipped" in path.read_text(), seconds=15)
        log = path.read_text()
        assert "degraded start" not in log
        assert "geo database reloaded" not in log, "a skipped job reloads nothing"
    cleanup_verified(process)
    print("PASS jobs run_if: fresh database skips the startup attempt")


def test_failed_job_keeps_serving_degraded():
    """A 404 job neither blocks the VPN nor invents a table."""
    CSV.unlink(missing_ok=True)
    with session("jobs-failure", args=jobs_config(f"http://{FILES}/missing.csv")) as (process, path):
        until(lambda: "vpn: degraded start" in path.read_text(), seconds=15)
        until(lambda: "job: update failed" in path.read_text(), seconds=30)
        until(lambda: "geo: missing (job update)" in path.read_text(), seconds=15)
        # The failed job never ran a reload.
        assert "geo database reloaded" not in path.read_text()
    cleanup_verified(process)
    print("PASS jobs failure: a broken download keeps the VPN degraded, not dead")


TESTS = [
    ("test_missing_database_degrades_then_reloads_live", test_missing_database_degrades_then_reloads_live),
    ("test_run_if_skips_when_the_database_is_fresh", test_run_if_skips_when_the_database_is_fresh),
    ("test_failed_job_keeps_serving_degraded", test_failed_job_keeps_serving_degraded),
]
