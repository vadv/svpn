# Tests

## Native checks — Linux and macOS

Run without root or a TUN interface:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
python3 tests/test_artifacts.py
python3 tests/test_groups.py
python3 tests/test_package.py
```

The Python self-checks use fake commands; they do not start Docker or change networking.
CI runs formatting, Clippy, and native tests in independent jobs. The network Docker
build compiles the release binary without repeating the native unit tests.

## Network checks — Docker Compose

Run from the repository root with Docker Compose available. The containers need
`/dev/net/tun` and `NET_ADMIN`; the scripts do not configure the host network.
The wrapper pins this repository's `compose.yaml` and the `svpn-test` project,
even when `COMPOSE_FILE` or `COMPOSE_PROJECT_NAME` is exported.
Each invocation first removes the existing test Compose containers and volumes,
then creates a fresh stack, network and SSH keys. **Do not run these commands in
parallel on one Docker host:** the project name and subnet are shared.

```sh
tests/run.sh                 # Original 40 integration calls, in their original order
tests/run.sh bootstrap       # One integration group
tests/run.sh --matrix udp    # Four UDP strategy matrix rows, in a fresh stack
tests/run.sh --matrix all    # All eight matrix rows; separate from integration
```

| Integration group | Checks |
| --- | --- |
| `bootstrap` | CLI/TOML, SSH identity/trust, TUN names, logging/stats, addresses, readiness |
| `lifecycle-pool` | Hooks, hostname resolution, pool recovery, SSH/heartbeat loss, cleanup, Checking |
| `udp` | Packet transfer, MTU, resource limits, forwarding/NAT, UDP ports, perf command |
| `tcp-auto` | RST delivery, idle teardown, TCP framing/ports, fallback and exhausted candidates |

Groups preserve the original relative order of their cases. Some cases cover
multiple transports. Matrix accepts `all`, `udp`, or `tcp-auto` and checks bulk
transfer, MTU, datagram delivery and a new exchange after 75 seconds idle.

CI runs the four integration groups and two matrix groups as six independent
Ubuntu jobs. Each job checks out the sources and builds its own containers; no
workspace, image, key volume or network is shared between jobs. Log artifacts
include the suite, group and run attempt in their names and expire after seven
days. No group waits for another job's result or restores its build cache.

Each invocation prints its unique `tests/.work/artifacts/run.*` directory.
Build, startup, runner, service and session logs remain after success or failure;
cleanup removes containers and key volumes. Do not upload the entire `.work`
directory: it can also contain generated keys and private field diagnostics.

`load.py`, `remote.py` and the diagnostic scripts are manual tools, not CI groups.
