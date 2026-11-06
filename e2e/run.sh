#!/usr/bin/env bash
set -euo pipefail
usage() {
    echo "Usage: $0 [--matrix] [all|bootstrap|lifecycle-pool|setup|udp|tcp-auto|reselect|recovery|sticky-asn|sticky|jobs|zombie]"
    echo "Matrix groups: all, udp, tcp-auto. Run groups sequentially on a local Docker host."
}
matrix=0
if [[ ${1-} == --matrix ]]; then
    matrix=1
    shift
fi
if (( $# > 1 )); then
    usage >&2
    exit 2
fi
export SVPN_TEST_GROUP=${1-all}
case "$SVPN_TEST_GROUP" in
    -h|--help) usage; exit 0 ;;
    all|udp|tcp-auto) ;;
    bootstrap|lifecycle-pool|setup|reselect|recovery|sticky-asn|sticky|jobs|zombie)
        if (( matrix )); then usage >&2; exit 2; fi ;;
    *) usage >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
compose_file=$PWD/compose.yaml
compose_project=svpn-test
startup=(server server2 target target_by dns files)
if [[ $SVPN_TEST_GROUP == setup ]]; then
    compose_file=$PWD/e2e/compose.setup.yaml
    compose_project=svpn-setup-test
    startup=(server)
fi
compose=(docker compose -f "$compose_file" -p "$compose_project")
mkdir -p e2e/.work/artifacts
export SVPN_TEST_ARTIFACTS
SVPN_TEST_ARTIFACTS=$(mktemp -d "$PWD/e2e/.work/artifacts/run.XXXXXX")
mkdir "$SVPN_TEST_ARTIFACTS/sessions"
printf 'Test artifacts: %s\n' "$SVPN_TEST_ARTIFACTS"
child=
interrupted=0

interrupt() {
    interrupted=$1
    if [[ -n "$child" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || true
    fi
}

run() {
    local log=$1 status=0
    shift
    if (( interrupted )); then
        return "$interrupted"
    fi
    # A separate process group lets cancellation reach both Docker and tee.
    set -m
    (set +m; "$@" 2>&1 | tee "$log") </dev/null &
    child=$!
    set +m
    if (( interrupted )); then
        interrupt "$interrupted"
    fi
    wait "$child" || status=$?
    if (( interrupted )); then
        wait "$child" || true
        status=$interrupted
    fi
    child=
    return "$status"
}

cleanup() {
    local status=$?
    if (( interrupted )); then
        status=$interrupted
    fi
    trap - EXIT
    # Signals must not skip down, including while compose logs is running.
    trap 'status=130' INT
    trap 'status=143' TERM
    "${compose[@]}" logs --no-color >"$SVPN_TEST_ARTIFACTS/services.log" 2>&1 || true
    if ! "${compose[@]}" down --volumes --remove-orphans >>"$SVPN_TEST_ARTIFACTS/services.log" 2>&1; then
        echo "Compose cleanup failed; inspect $SVPN_TEST_ARTIFACTS/services.log" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'interrupt 130' INT
trap 'interrupt 143' TERM

run "$SVPN_TEST_ARTIFACTS/preflight.log" "${compose[@]}" down --volumes --remove-orphans
run "$SVPN_TEST_ARTIFACTS/build.log" "${compose[@]}" build
run "$SVPN_TEST_ARTIFACTS/startup.log" "${compose[@]}" up -d --wait "${startup[@]}"
if (( matrix )); then
    run "$SVPN_TEST_ARTIFACTS/runner.log" "${compose[@]}" run --rm --no-deps -T client \
        python3 -u /e2e/matrix.py --group "$SVPN_TEST_GROUP"
else
    run "$SVPN_TEST_ARTIFACTS/runner.log" "${compose[@]}" run --rm --no-deps -T client
fi
