# Tests

Rust integration targets live in `tests/`. The Python E2E harness lives in
`e2e/` — no Python suites or shell runners remain in `tests/`. Shared Rust
fixtures are in `tests/common/`.

## Local checks — Linux and macOS

No root, TUN device or Docker is needed:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
uvx ruff@0.14.3 check
uvx ruff@0.14.3 format --check
python3 e2e/test_artifacts.py
python3 e2e/test_groups.py
python3 e2e/test_package.py
node --test e2e/test_dashboard.mjs
```

`e2e/test_artifacts.py`, `e2e/test_groups.py` and `e2e/test_package.py` are
self-checks of the harness itself: they use fake commands, never start Docker
and never change networking. `test_groups.py` pins suite case order and counts
— changing a suite without updating it fails the check. CI runs ruff with
`pipx run ruff==0.14.3`; locally `uvx` with the same pinned version is enough.

The dashboard calculations are pure ES modules, so `node --test` needs no npm
dependencies. A real-browser check is optional locally:

```sh
node e2e/test_dashboard_browser.mjs          # needs Chrome; CHROME overrides the path
DASHBOARD_SCREENSHOTS=e2e/.work/dashboard-screenshots node e2e/test_dashboard_browser.mjs
```

It starts its own fixture HTTP server, runs UI assertions in headless Chrome,
checks 1440 px and 390 px layouts and optionally writes screenshots. CI runs it
in the Linux native job. `tests/proc_stats.rs` covers `/proc` parsing, unit
conversion, peak-RSS fallback and the `process` JSON shape; `node --test` covers
CPU-percent derivation and uptime; the Chrome check asserts the rendered RAM/CPU
readout, stale handling and the labelled peak-RSS fallback.

## Network checks — Docker Compose

Run from the repository root with Docker Compose available. Containers need
`/dev/net/tun`, `NET_ADMIN` and `NET_RAW`; the wrapper never configures the host
network. It pins this repository's `compose.yaml` and the `svpn-test` project,
even when `COMPOSE_FILE` or `COMPOSE_PROJECT_NAME` is exported. Each invocation
first removes the existing test containers and volumes, then builds a fresh
image, network and SSH keys. **Do not run these commands in parallel on one
Docker host:** the project name and subnet are shared.

```sh
e2e/run.sh                       # all integration groups, sequentially
e2e/run.sh bootstrap             # one integration group
e2e/run.sh --matrix udp          # matrix rows in a fresh stack
e2e/run.sh --matrix all          # all matrix rows
```

Integration groups: `bootstrap`, `lifecycle-pool`, `udp`, `tcp-auto`,
`reselect`, `recovery`, `sticky-asn`, `sticky`, `jobs`, `zombie`. Matrix groups:
`udp`, `tcp-auto`, `all`. `setup` is a separate suite on its own rig, using
`e2e/compose.setup.yaml` and the `svpn-setup-test` project.

| Group | Checks |
| --- | --- |
| `bootstrap` | CLI/HCL config, SSH identity and trust, TUN names, logging and stats, address assignment, readiness |
| `lifecycle-pool` | hooks, DNS resolution, pool failover, SSH/heartbeat loss, cleanup, reconnect |
| `udp` | packet transfer, MTU, resource limits, forwarding/NAT, UDP port range, `svpn perf` |
| `tcp-auto` | TCP framing, RST handling, idle teardown, fallback and exhausted candidates |
| `reselect`, `recovery`, `zombie` | candidate reselection, link recovery, flow-table admission and TTL |
| `sticky`, `sticky-asn` | first-match rules, local exit, ASN grouping, failover and pinned owners |
| `jobs` | background jobs, gate outcomes, geo/country reloads and status reporting |
| `setup` | provisioning, distro families, downgrade and setup statuses |
| matrix `udp` / `tcp-auto` | bulk transfer, MTU, datagram delivery, a new exchange after a long idle gap |

CI runs 11 isolated network jobs: eight integration groups, two matrix groups
and `setup`. Each job checks out the sources and builds its own containers —
no workspace, image, key volume or network is shared between jobs. Native
tests, formatting, Clippy and Python lint run as independent jobs; network jobs
compile the release binary but do not repeat the native unit tests.

Each invocation prints its unique `e2e/.work/artifacts/run.*` directory. Build,
startup, runner, service and session logs survive both success and failure;
cleanup removes containers and key volumes. Upload only explicit log paths —
the whole `.work` tree may contain generated keys and private diagnostics.

`e2e/_lib.py` is the shared harness library, `e2e/integration.py` the runner,
`e2e/suite_*.py` the case groups. `e2e/load.py`, `e2e/remote.py` and the
`diag_*.py` scripts are manual tools, not CI groups.
