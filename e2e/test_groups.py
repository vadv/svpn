"""Check group coverage, ordering and dispatch without Docker or network access."""

import collections
import contextlib
import io
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import integration
import matrix
import suite_bootstrap
import suite_pool
import suite_recovery
import suite_reselect
import suite_sticky_asn
import suite_tcp_auto
import suite_udp
from test_artifacts import check

# Independent snapshot of the pre-split runner: keep every case and its order.
BASELINE = """
test_lifecycle_hooks test_configuration test_server_hooks test_authentication test_known_hosts_tofu
test_agent_identity test_no_ssh_binary test_custom_tun_name test_kernel_tun_name
test_log_levels test_client_stats test_secondary_server_address test_hostname_servers
test_pool_two_servers test_pool_udp_ports test_pool_failover test_pool_backoff
test_pool_all_down test_data test_client_rst_delivery test_idle_tcp_survival
test_low_fd_limit test_ssh_loss test_heartbeat_loss test_blocked_stderr
test_server_blocked_stderr test_sigkill_takeover test_masquerade test_udp_port_range
test_tcp_transport test_tcp_ephemeral test_tcp_udp_blocked test_tcp_teardown
test_tcp_l0_l1 test_tcp_camouflage_ssh test_auto_tcp_fallback test_auto_exhausted
test_readiness_requires_kernel_reply test_checking_recovers_without_ssh_restart
test_checking_preserves_active_tcp_flows test_perf
test_auto_assignment_and_restart test_auto_two_clients_one_server test_auto_explicit_pair_lock
test_auto_pool_shared_pair
""".split()
RESELECT_BASELINE = """
test_udp_reselect_after_ban_expiry test_degraded_incumbent_switches_and_drains
test_incumbent_drift_ramp_switches test_symmetric_noise_does_not_switch
""".split()
RECOVERY_BASELINE = """
test_recovery_restores_tcp_without_second_accept
test_recovery_does_not_retransmit_uncertain_udp
test_recovery_without_alternative_closes_within_budget
""".split()
STICKY_BASELINE = """
test_sticky_dst test_balance_diff test_failover_move test_restart_restore
test_country_asn_scope test_local_exits_and_vpn
""".split()
MATRIX_BASELINE = (
    ("mosh", ("--mimic", "mosh")),
    ("obfs", ("--mimic", "obfs")),
    ("quic", ("--mimic", "quic")),
    ("webrtc", ("--mimic", "webrtc")),
    ("tcp-none", ("--mimic", "none", "--tcp-port", "4190")),
    ("tcp-banner", ("--mimic", "ssh", "--tcp-port", "4191")),
    ("tcp-ssh", ("--mimic", "ssh", "--tcp-port", "4192")),
    ("auto", ("--tcp-port", "4193")),
)


# suite_pool's run() invokes these hooks sub-tests directly; they are not registry entries.
HOOKS_SUBTESTS = {
    "test_scripts",
    "test_up_barrier_and_routes",
    "test_up_failures",
    "test_signals_during_up",
    "test_failed_down_and_partial_up",
    "test_fatal_during_up",
    "test_blocked_hook_output",
    "test_pool_transitions",
}


def integration_groups():
    suites = {
        "bootstrap": suite_bootstrap,
        "lifecycle-pool": suite_pool,
        "udp": suite_udp,
        "tcp-auto": suite_tcp_auto,
        "reselect": suite_reselect,
        "recovery": suite_recovery,
        "sticky-asn": suite_sticky_asn,
    }
    assert set(suites) == set(integration.GROUPS)
    by_fn = {test: (group, name) for group, suite in suites.items() for name, test in suite.TESTS}
    tests = [test for _, test in integration.TESTS]
    original = BASELINE + RESELECT_BASELINE + RECOVERY_BASELINE + STICKY_BASELINE
    assert [by_fn[test][1] for test in tests] == original, "original order"
    assert [by_fn[test][0] for test in tests] == [owner for owner, _ in integration.TESTS]
    assert len(tests) == len(set(tests)) == len(by_fn), "a test is assigned twice or dropped"
    for group, suite in suites.items():
        discovered = {
            test for name, test in vars(suite).items() if name.startswith("test_") and callable(test)
        }
        assigned = {test for _, test in suite.TESTS}
        extra = discovered - assigned
        expected = {getattr(suite, name) for name in HOOKS_SUBTESTS if group == "lifecycle-pool"}
        assert extra == expected, (group, extra, "every test must be assigned")
    assert collections.Counter(owner for owner, _ in integration.TESTS) == {
        "bootstrap": 12,
        "lifecycle-pool": 18,
        "udp": 5,
        "tcp-auto": 10,
        "reselect": 4,
        "recovery": 3,
        "sticky-asn": 6,
    }
    for group in ("all", *integration.GROUPS):
        expected = [test for owner, test in integration.TESTS if group in ("all", owner)]
        for args in (["--group", group], []):
            called = []
            stubs = {test: (lambda test=test, called=called: called.append(test)) for test in tests}
            registry = [(owner, stubs[test]) for owner, test in integration.TESTS]
            with (
                patch.object(integration, "TESTS", registry),
                patch.object(integration, "scrub_firewall"),
                patch.object(integration, "command", return_value=SimpleNamespace(returncode=1)),
                patch.object(sys, "argv", ["integration.py", *args]),
                patch.dict(os.environ, {"SVPN_TEST_GROUP": group}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                integration.main()
            assert called == expected, (group, args)
    print(f"PASS integration: {len(tests)} cases assigned once, CLI/env selection and original order")


def matrix_groups():
    assert tuple((name, tuple(args)) for name, args in matrix.CONFIGS) == MATRIX_BASELINE
    assigned = [name for names in matrix.GROUPS.values() for name in names]
    assert collections.Counter(assigned) == collections.Counter(name for name, _ in MATRIX_BASELINE)
    for group in ("all", *matrix.GROUPS):
        called = []
        expected = [
            (name, args) for name, args in MATRIX_BASELINE if group == "all" or name in matrix.GROUPS[group]
        ]

        def append_call(name, args, called=called):
            called.append((name, tuple(args)))
            return {}

        with (
            patch.object(matrix, "command", return_value=SimpleNamespace(returncode=1)),
            patch.object(matrix, "run_config", side_effect=append_call),
            patch.object(matrix.time, "sleep"),
            patch.object(sys, "argv", ["matrix.py", "--group", group]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            matrix.main()
        assert called == expected, group
    print("PASS matrix: 8 rows assigned once, original order and dispatch")


def reselect_log_patterns():
    log = "[server] flow_open role=server id=7 generation=1 channel=2 transport=tcp"
    assert suite_reselect.tcp_flow_ids(log) == {"7"}
    print("PASS reselect logs: generation-aware TCP flow parsing")


def local_exit_full_tunnel_guard():
    path = pathlib.Path(suite_sticky_asn.__file__).parent / "config" / "geo-up.sh"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                suite_sticky_asn.install_full_tunnel_routes()
            except AssertionError:
                pass
            else:
                raise AssertionError("route hook guard did not reject local-exit")
    finally:
        path.unlink()
    print("PASS local-exit routes: legacy Ready hooks cannot overwrite full-tunnel routes")


def local_exit_cleanup_requires_ownership():
    source = pathlib.Path("README.md").read_text()
    script = re.search(r"server-down = '''\n(.*?)\n'''", source, re.S).group(1)
    with tempfile.TemporaryDirectory(prefix="svpn-cleanup-test-") as directory:
        root = pathlib.Path(directory)
        log = root / "ip.log"
        fake_ip = root / "ip"
        fake_ip.write_text(
            "#!/bin/sh\n"
            'echo "$@" >> "$IP_LOG"\n'
            'if [ "$1 $2 $3 $4" = "-4 route show default" ]; then\n'
            "    echo 'default via 192.0.2.1 dev eth0'\n"
            "fi\n",
            encoding="utf-8",
        )
        fake_ip.chmod(0o700)
        env = os.environ.copy()
        env.update(
            PATH=f"{root}:{env['PATH']}",
            IP_LOG=str(log),
            SVPN_PEER_ADDR="10.77.0.2",
            SVPN_SESSION_ID=f"cleanup-test-{os.getpid()}",
        )
        result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        calls = log.read_text()
        assert "rule del" not in calls and "route del" not in calls, calls
    print("PASS local-exit cleanup: rejected startup cannot delete foreign routes")


def flow_cleanup_statistics():
    def snapshot(server, opened, closed, active=0, failed=0):
        prefix = "[server] " if server else ""
        return (
            f"t+ 250.000s {prefix}heartbeat received stats=Stats {{ "
            f"opened_flows: {opened}, open_failed_flows: {failed}, "
            f"closed_flows: {closed}, active_flows: {active} }}\n"
        )

    done = snapshot(False, 128, 128) + snapshot(True, 128, 128)
    assert suite_udp._flows_reclaimed(done, 128)
    assert not suite_udp._flows_reclaimed("", 128)
    assert not suite_udp._flows_reclaimed(snapshot(False, 128, 128), 128)
    assert not suite_udp._flows_reclaimed(snapshot(False, 0, 0) + snapshot(True, 0, 0), 128)
    assert not suite_udp._flows_reclaimed(done + snapshot(True, 129, 128, active=1), 128)
    assert not suite_udp._flows_reclaimed(done + snapshot(False, 129, 129, failed=1), 128)
    print("PASS flow cleanup: both peers, latest counters, no dependence on per-flow debug logs")


def matrix_diagnostics():
    def make_wait(stalled, progress, calls):
        def wait_side_effect(_):
            if not stalled:
                progress[0] += 1
            return calls.pop(0)

        return wait_side_effect

    for stalled, failure in [(False, False), (True, False), (True, True)]:
        progress = [0]
        calls = [False, False, True]
        stop = Mock()
        stop.wait.side_effect = make_wait(stalled, progress, calls)
        output = io.StringIO()
        results = [
            subprocess.TimeoutExpired("ss", 5) if failure else SimpleNamespace(stdout="client sockets"),
            SimpleNamespace(stdout="server sockets"),
        ]
        with (
            patch.object(matrix, "command", side_effect=results) as command,
            contextlib.redirect_stdout(output),
        ):
            matrix.tcp_diagnostics(stop, progress)
        assert command.call_count == (2 if stalled else 0)
        if stalled:
            assert "TCP-DIAGNOSTICS client" in output.getvalue()
            assert "server sockets" in output.getvalue()
            assert all(call.kwargs == {"check": False, "timeout": 5} for call in command.call_args_list)
            for call in command.call_args_list:
                script = call.args[0][-1]
                assert "uname -r; ss -tinm; nstat -az" in script
                assert "timeout 2 tcpdump -i svpn0 -nn -S -tt -s 96 -c 20 'tcp port 9000'" in script
                assert "-A" not in script and "-X" not in script
        else:
            assert not output.getvalue()
    print("PASS matrix diagnostics: silent fast path, both peers, bounded failures")


def invalid_groups():
    for module, args in [
        (integration, ["--group", "unknown"]),
        (integration, []),
        (matrix, ["--group", "bootstrap"]),
        (matrix, ["--unknown"]),
    ]:
        with (
            patch.object(module, "command", return_value=SimpleNamespace(returncode=1)) as command,
            patch.object(integration, "TESTS", []),
            patch.object(integration, "scrub_firewall"),
            patch.object(matrix, "run_config", side_effect=AssertionError("unexpected matrix run")),
            patch.object(sys, "argv", [module.__file__, *args]),
            patch.dict(os.environ, {"SVPN_TEST_GROUP": "unknown"}),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            try:
                module.main()
            except SystemExit as error:
                assert error.code == 2
            else:
                raise AssertionError("invalid group accepted")
            command.assert_not_called()
    print("PASS invalid Python selectors fail before network setup")


def shell_groups():
    for group in ("all", *integration.GROUPS):
        calls = check("success", 0, (group,))
        assert all(line.endswith("group=" + group) for line in calls.splitlines())
        assert "/e2e/matrix.py" not in calls
    for group in ("all", *matrix.GROUPS):
        calls = check("success", 0, ("--matrix", group))
        assert "python3 -u /e2e/matrix.py --group " + group in calls
        assert all(line.endswith("group=" + group) for line in calls.splitlines())
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        (root / "e2e").mkdir()
        (root / "bin").mkdir()
        script = root / "e2e/run.sh"
        shutil.copy2(pathlib.Path(__file__).with_name("run.sh"), script)
        docker = root / "bin/docker"
        docker.write_text("#!/bin/sh\necho unexpected Docker invocation >&2\nexit 99\n")
        docker.chmod(0o755)
        env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"])
        for args, status in [
            (("--help",), 0),
            (("unknown",), 2),
            (("udp", "extra"), 2),
            (("--matrix", "bootstrap"), 2),
            (("",), 2),
        ]:
            result = subprocess.run(
                ["bash", str(script), *args], env=env, capture_output=True, text=True, timeout=5
            )
            assert result.returncode == status, (args, result.stdout, result.stderr)
            assert not (root / "e2e/.work").exists(), "selector must fail before side effects"
    print("PASS shell selection, matrix routing and fail-fast validation")


if __name__ == "__main__":
    integration_groups()
    matrix_groups()
    matrix_diagnostics()
    reselect_log_patterns()
    local_exit_full_tunnel_guard()
    local_exit_cleanup_requires_ownership()
    flow_cleanup_statistics()
    invalid_groups()
    shell_groups()
