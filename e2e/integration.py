"""Exercise real SSH, TUN, UDP data paths and fail-stop in Linux containers.
Test bodies live in the suite_* modules; rig helpers live in _lib.py (shared with matrix.py/load.py)."""

import argparse
import os

import suite_bootstrap
import suite_pool
import suite_recovery
import suite_reselect
import suite_sticky_asn
import suite_tcp_auto
import suite_udp

# diag_dwell129.py imports PEER, session, ssh, command and until from this module.
from _lib import SERVER, command, ssh

GROUPS = ("bootstrap", "lifecycle-pool", "udp", "tcp-auto", "reselect", "recovery", "sticky-asn")

# The pre-split registry interleaved the groups; keep the exact overall sequence.
_SEQUENCE = (
    ("lifecycle-pool",)
    + ("bootstrap",) * 11
    + ("lifecycle-pool",) * 6
    + ("udp",)
    + ("tcp-auto",) * 2
    + ("udp",)
    + ("lifecycle-pool",) * 5
    + ("udp",) * 2
    + ("tcp-auto",) * 8
    + ("bootstrap",)
    + ("lifecycle-pool",) * 2
    + ("udp",)
    + ("lifecycle-pool",) * 4
    + ("reselect",) * 4
    + ("recovery",) * 3
    + ("sticky-asn",) * 8
)
_SUITES = {
    "bootstrap": suite_bootstrap,
    "lifecycle-pool": suite_pool,
    "udp": suite_udp,
    "tcp-auto": suite_tcp_auto,
    "reselect": suite_reselect,
    "recovery": suite_recovery,
    "sticky-asn": suite_sticky_asn,
}
_PENDING = {group: iter(suite.TESTS) for group, suite in _SUITES.items()}
TESTS = []
for _group in _SEQUENCE:
    _name, _test = next(_PENDING[_group])
    TESTS.append((_group, _test))


def scrub_firewall():
    # Idempotent scrub of fault-test rules: after a killed run (SIGKILL,
    # wrapper timeout) finally never runs and the rule leaks into the container,
    # breaking the following runs (we saw an INPUT udp DROP tearing down UDP channel probes).
    for rule in (["-p", "tcp", "--dport", "22", "-j", "DROP"],):
        for target in ("OUTPUT",):
            while command(["iptables", "-w", "-D", target] + rule, check=False).returncode == 0:
                pass
    for script in ("iptables -w -D OUTPUT -p udp -j DROP", "iptables -w -D INPUT -p udp -j DROP"):
        while ssh(script, check=False).returncode == 0:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ("all",) + GROUPS
    parser.add_argument("--group", choices=choices, default=os.environ.get("SVPN_TEST_GROUP", "all"))
    group = parser.parse_args().group
    if group not in choices:
        parser.error("invalid SVPN_TEST_GROUP")
    scrub_firewall()
    for rule in (["-d", SERVER, "-p", "tcp", "--dport", "22", "-j", "DROP"],):
        while command(["iptables", "-w", "-D", "OUTPUT"] + rule, check=False).returncode == 0:
            pass
    for owner, test in TESTS:
        if group == "all" or owner == group:
            test()
    label = "ALL" if group == "all" else group.upper()
    print(f"{label} COMPOSE TESTS PASSED", flush=True)


if __name__ == "__main__":
    main()
