#!/usr/bin/env bash

# Run the complete private-Sphere journey. Account funding, L1 approvals,
# and redacted-RPC authentication are deliberately
# outside the scenario measurement.
set -Eeuo pipefail

bench_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scenario-reporting.sh
source "$bench_dir/scenario-reporting.sh"

die() { echo "error: $*" >&2; exit 1; }
need() { [[ -n "${!1:-}" ]] || die "$1 must be set"; }
uint() { [[ "${!1:-}" =~ ^[0-9]+$ ]] || die "$1 must be an unsigned integer"; }
positive_rate() {
    local value="${!1:-}"
    if ! [[ "$value" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
        ! awk -v value="$value" 'BEGIN { exit !(value > 0 && value <= 999999999) }'; then
        die "$1 must be a positive decimal no greater than 999999999"
    fi
}
load_benchmark_mnemonic() {
    local mode

    need SPHERES_BENCH_MNEMONIC_FILE
    [[ ! -L "$SPHERES_BENCH_MNEMONIC_FILE" ]] ||
        die "SPHERES_BENCH_MNEMONIC_FILE must not be a symbolic link"
    [[ -f "$SPHERES_BENCH_MNEMONIC_FILE" ]] ||
        die "SPHERES_BENCH_MNEMONIC_FILE must be a regular file"
    [[ -s "$SPHERES_BENCH_MNEMONIC_FILE" ]] ||
        die "SPHERES_BENCH_MNEMONIC_FILE must not be empty"
    [[ -r "$SPHERES_BENCH_MNEMONIC_FILE" ]] ||
        die "SPHERES_BENCH_MNEMONIC_FILE must be readable"

    mode="$(stat -c '%a' -- "$SPHERES_BENCH_MNEMONIC_FILE" 2>/dev/null || stat -f '%Lp' "$SPHERES_BENCH_MNEMONIC_FILE")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] ||
        die "could not validate SPHERES_BENCH_MNEMONIC_FILE permissions"
    (( (8#$mode & 8#077) == 0 )) ||
        die "SPHERES_BENCH_MNEMONIC_FILE must not be accessible by group or other users"

    SPHERES_BENCH_MNEMONIC="$(<"$SPHERES_BENCH_MNEMONIC_FILE")"
    [[ "$SPHERES_BENCH_MNEMONIC" =~ [^[:space:]] ]] ||
        die "SPHERES_BENCH_MNEMONIC_FILE must contain a mnemonic"
    export SPHERES_BENCH_MNEMONIC
}

SPHERES_BENCH_NEOBANK_PRESET="${SPHERES_BENCH_NEOBANK_PRESET:-full-journey}"
case "$SPHERES_BENCH_NEOBANK_PRESET" in
    encrypted-deposit) scenario_file=encrypted-deposit-scenario.yml; leases_per_journey=1 ;;
    full-journey) scenario_file=private-flow-scenario.yml; leases_per_journey=2 ;;
    *) die "unsupported Arc USDC preset: $SPHERES_BENCH_NEOBANK_PRESET (available: encrypted-deposit, full-journey)" ;;
esac

load_benchmark_mnemonic
for name in L1_RPC_URL L1_WS_RPC_URL SPHERE_RPC_URL SPHERE_WS_RPC_URL SPHERE_REDACTED_RPC_URL \
    L1_PORTAL_ADDRESS SPHERES_BENCH_EXPECTED_L1_CHAIN_ID SPHERES_BENCH_EXPECTED_SPHERE_CHAIN_ID \
    SPHERES_BENCH_EXPECTED_SPHERE_ID
do need "$name"; done

SPHERES_BENCH_TOKEN=0x3600000000000000000000000000000000000000
SPHERES_BENCH_SEED="${SPHERES_BENCH_SEED:-1}"
SPHERES_BENCH_ACCOUNT_START="${SPHERES_BENCH_ACCOUNT_START:-16}"
SPHERES_BENCH_ACCOUNTS="${SPHERES_BENCH_ACCOUNTS:-100}"
SPHERES_BENCH_COUNT="${SPHERES_BENCH_COUNT:-100}"
SPHERES_BENCH_TPS="${SPHERES_BENCH_TPS:-20}"
SPHERES_BENCH_MAX_CONCURRENT="${SPHERES_BENCH_MAX_CONCURRENT:-12}"
SPHERES_BENCH_DEPOSIT_AMOUNT="${SPHERES_BENCH_DEPOSIT_AMOUNT:-10000000}"
SPHERES_BENCH_ACTIVITY_AMOUNT="${SPHERES_BENCH_ACTIVITY_AMOUNT:-1}"
SPHERES_BENCH_WITHDRAWAL_AMOUNT="${SPHERES_BENCH_WITHDRAWAL_AMOUNT:-1000000}"
SPHERES_BENCH_OUTPUT="${SPHERES_BENCH_OUTPUT:-target/spheres-benchmark/neobank-e2e}"
SPHERES_BENCH_REPORT="${SPHERES_BENCH_REPORT:-target/spheres-benchmark/report-neobank-e2e.json}"
SPHERES_BENCH_RENDERED_SCENARIO="${SPHERES_BENCH_RENDERED_SCENARIO:-$SPHERES_BENCH_OUTPUT/scenario.rendered.yml}"
SPHERES_BENCH_SPF_RANGE="${SPHERES_BENCH_SPF_RANGE:-target/spheres-benchmark/spf-range.env}"
SPHERES_BENCH_AUTH_TTL_SECS="${SPHERES_BENCH_AUTH_TTL_SECS:-600}"
SPHERES_BENCH_AUTH_REFRESH_SECS="${SPHERES_BENCH_AUTH_REFRESH_SECS:-60}"
SPHERES_BENCH_STEP_TIMEOUT="${SPHERES_BENCH_STEP_TIMEOUT:-10m}"
# Trace every journey (up to 1000) so the CI notifier can test per-journey latency.
SPHERES_BENCH_SAMPLE_INSTANCES="${SPHERES_BENCH_SAMPLE_INSTANCES:-$(( 10#$SPHERES_BENCH_COUNT < 1000 ? 10#$SPHERES_BENCH_COUNT : 1000 ))}"
SPHERES_BENCH_RUN_ID="${SPHERES_BENCH_RUN_ID:-local}"
SPHERES_BENCH_L1_QUERY_RPC_URL="${SPHERES_BENCH_L1_QUERY_RPC_URL:-$L1_RPC_URL}"
SPHERES_BENCH_ACCOUNT_END="${SPHERES_BENCH_ACCOUNT_END:-$((10#$SPHERES_BENCH_ACCOUNT_START + 10#$SPHERES_BENCH_ACCOUNTS))}"
SPHERES_BENCH_INBOX="${SPHERES_BENCH_INBOX:-0x1c00000000000000000000000000000000000001}"
SPHERES_BENCH_OUTBOX="${SPHERES_BENCH_OUTBOX:-0x1c00000000000000000000000000000000000002}"
SPHERES_BENCH_L1_MAX_FEE_PER_GAS="${SPHERES_BENCH_L1_MAX_FEE_PER_GAS:-$(cast gas-price --rpc-url "$L1_RPC_URL")}"
SPHERES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS=0
SPHERES_BENCH_SPHERE_MAX_FEE_PER_GAS="${SPHERES_BENCH_SPHERE_MAX_FEE_PER_GAS:-$(cast gas-price --rpc-url "$SPHERE_RPC_URL")}"
SPHERES_BENCH_SPHERE_MAX_PRIORITY_FEE_PER_GAS=0
for name in SPHERES_BENCH_ACCOUNT_START SPHERES_BENCH_ACCOUNTS SPHERES_BENCH_COUNT \
    SPHERES_BENCH_MAX_CONCURRENT SPHERES_BENCH_DEPOSIT_AMOUNT SPHERES_BENCH_ACTIVITY_AMOUNT \
    SPHERES_BENCH_WITHDRAWAL_AMOUNT SPHERES_BENCH_SAMPLE_INSTANCES SPHERES_BENCH_SEED \
    SPHERES_BENCH_ACCOUNT_END SPHERES_BENCH_EXPECTED_L1_CHAIN_ID \
    SPHERES_BENCH_EXPECTED_SPHERE_CHAIN_ID SPHERES_BENCH_EXPECTED_SPHERE_ID \
    SPHERES_BENCH_L1_MAX_FEE_PER_GAS SPHERES_BENCH_SPHERE_MAX_FEE_PER_GAS
do uint "$name"; done
positive_rate SPHERES_BENCH_TPS
(( 10#$SPHERES_BENCH_ACCOUNTS > 0 && 10#$SPHERES_BENCH_COUNT > 0 )) || die "accounts and count must be positive"
(( 10#$SPHERES_BENCH_MAX_CONCURRENT > 0 )) || die "max concurrency must be positive"
(( 10#$SPHERES_BENCH_SAMPLE_INSTANCES > 0 )) ||
    die "sample instances must be positive"
sample_instances="$SPHERES_BENCH_SAMPLE_INSTANCES"
if (( 10#$SPHERES_BENCH_COUNT < 10#$sample_instances )); then
    sample_instances="$SPHERES_BENCH_COUNT"
fi
required_accounts=$((10#$SPHERES_BENCH_MAX_CONCURRENT * leases_per_journey))
(( required_accounts <= 10#$SPHERES_BENCH_ACCOUNTS )) ||
    die "$SPHERES_BENCH_NEOBANK_PRESET requires at least $required_accounts accounts for max-concurrent=$SPHERES_BENCH_MAX_CONCURRENT"
export L1_RPC_URL L1_WS_RPC_URL SPHERE_RPC_URL SPHERE_WS_RPC_URL SPHERE_REDACTED_RPC_URL
export L1_PORTAL_ADDRESS SPHERES_BENCH_L1_QUERY_RPC_URL SPHERES_BENCH_MNEMONIC
export SPHERES_BENCH_ACCOUNT_START SPHERES_BENCH_ACCOUNT_END SPHERES_BENCH_ACCOUNTS
export SPHERES_BENCH_EXPECTED_L1_CHAIN_ID SPHERES_BENCH_EXPECTED_SPHERE_CHAIN_ID
export SPHERES_BENCH_EXPECTED_SPHERE_ID SPHERES_BENCH_INBOX SPHERES_BENCH_OUTBOX
export SPHERES_BENCH_L1_MAX_FEE_PER_GAS SPHERES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS
export SPHERES_BENCH_SPHERE_MAX_FEE_PER_GAS SPHERES_BENCH_SPHERE_MAX_PRIORITY_FEE_PER_GAS
export SPHERES_BENCH_TOKEN SPHERES_BENCH_SEED SPHERES_BENCH_ACTIVITY_AMOUNT
export SPHERES_BENCH_DEPOSIT_AMOUNT SPHERES_BENCH_WITHDRAWAL_AMOUNT

stage_start() { echo "neobank stage=start run_id=$SPHERES_BENCH_RUN_ID preset=$SPHERES_BENCH_NEOBANK_PRESET stage=$1"; }
stage_end() { echo "neobank stage=end run_id=$SPHERES_BENCH_RUN_ID preset=$SPHERES_BENCH_NEOBANK_PRESET stage=$1"; }

read_l1_uint() {
    local address="$1" signature="$2"
    shift 2
    local value
    value="$(cast call "$address" "$signature" "$@" --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    [[ "$value" =~ ^[0-9]+$ ]] || die "could not read $signature from $address"
    printf '%s\n' "$value"
}

assert_scenario_report() {
    local report="$1" expected="$2" label="$3"
    jq -e --argjson expected "$expected" '
        .started == $expected and
        .completed == $expected and
        .failed == 0 and
        .timed_out == 0
    ' "$report" >/dev/null || die "$label did not complete successfully"
}

txgen_bin="${TXGEN_BIN:-txgen-sphere}"
for command in "$txgen_bin" awk cast curl jq; do
    command -v "$command" >/dev/null || die "missing $command"
done

neobank_specs="$bench_dir/neobank"
scenario_path="$neobank_specs/$scenario_file"
portal_approval_scenario="$neobank_specs/l1-portal-approval-scenario.yml"
mkdir -p "$SPHERES_BENCH_OUTPUT" "$(dirname "$SPHERES_BENCH_RENDERED_SCENARIO")"
secret_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/spheres-neobank-auth.XXXXXX")"
chmod 700 "$secret_dir"
export SPHERES_BENCH_SPHERE_AUTH_MAP="$secret_dir/sphere-auth.json"
auth_pid=""
cleanup() {
    local status=$?
    [[ -z "$auth_pid" ]] || { kill -TERM "$auth_pid" 2>/dev/null || true; wait "$auth_pid" 2>/dev/null || true; }
    rm -f -- "$secret_dir/sphere-auth.json" "$secret_dir/auth-token-map.log"
    rmdir "$secret_dir" 2>/dev/null || true
    unset SPHERES_BENCH_MNEMONIC
    exit "$status"
}
trap cleanup EXIT INT TERM

run_setup_scenario() {
    local stage="$1" scenario="$2" count="$3" report="$4" context="${5:-}"
    local starts_per_second="${6:-0}"
    local concurrency="${7:-$SPHERES_BENCH_MAX_CONCURRENT}"
    if (( 10#$concurrency > 10#$SPHERES_BENCH_MAX_CONCURRENT )); then concurrency="$SPHERES_BENCH_MAX_CONCURRENT"; fi
    if (( 10#$concurrency > 10#$count )); then concurrency="$count"; fi

    echo "neobank stage=start run_id=$SPHERES_BENCH_RUN_ID preset=$SPHERES_BENCH_NEOBANK_PRESET stage=$stage${context:+ $context}"
    "$txgen_bin" scenario run \
        --scenario "$scenario" --count "$count" --starts-per-second "$starts_per_second" \
        --max-in-flight "$concurrency" --max-rpc-in-flight "$concurrency" \
        --failure-policy fail-fast --step-timeout "$SPHERES_BENCH_STEP_TIMEOUT" \
        --seed "$SPHERES_BENCH_SEED" --report "$report"
    assert_scenario_report "$report" "$count" "$stage"
    echo "neobank stage=end run_id=$SPHERES_BENCH_RUN_ID preset=$SPHERES_BENCH_NEOBANK_PRESET stage=$stage${context:+ $context}"
}
stage_start render_scenario
"$txgen_bin" scenario render \
    --scenario "$scenario_path" \
    --output "$SPHERES_BENCH_RENDERED_SCENARIO"
[[ -s "$SPHERES_BENCH_RENDERED_SCENARIO" ]] ||
    die "txgen did not render the selected neobank scenario"
stage_end render_scenario
run_setup_scenario \
    portal_approval "$portal_approval_scenario" "$SPHERES_BENCH_ACCOUNTS" \
    "$SPHERES_BENCH_OUTPUT/portal-approval-report.json" "approval_round=portal"
# The auth map is intentionally mode 0600 and is never copied to benchmark artifacts.
stage_start auth_token_map
"$txgen_bin" auth-token-map --spec "$neobank_specs/sphere-flow.yml" --pool users \
    --sphere-id "$SPHERES_BENCH_EXPECTED_SPHERE_ID" \
    --chain-id "$SPHERES_BENCH_EXPECTED_SPHERE_CHAIN_ID" \
    --ttl-secs "$SPHERES_BENCH_AUTH_TTL_SECS" \
    --refresh-before-secs "$SPHERES_BENCH_AUTH_REFRESH_SECS" \
    --watch --output "$secret_dir/sphere-auth.json" >"$secret_dir/auth-token-map.log" 2>&1 &
auth_pid=$!
for _ in $(seq 1 60); do [[ -f "$secret_dir/sphere-auth.json" ]] && break; sleep 1; done
[[ -f "$secret_dir/sphere-auth.json" ]] || die "timed out creating private Sphere auth map"
jq -e 'to_entries | all(.[]; (.key | type) == "string" and (.value | type) == "string")' \
    "$secret_dir/sphere-auth.json" >/dev/null ||
    die "private Sphere auth map is malformed"
jq -S 'keys | sort' "$secret_dir/sphere-auth.json" >"$SPHERES_BENCH_OUTPUT/accounts.json"
jq -e --argjson expected "$SPHERES_BENCH_ACCOUNTS" '
    length == $expected and
    all(.[]; type == "string") and
    (unique | length) == $expected
' "$SPHERES_BENCH_OUTPUT/accounts.json" >/dev/null ||
    die "auth map did not derive the expected unique benchmark account pool"
stage_end auth_token_map
[[ -z "${SPHERES_BENCH_SETTLEMENT_FILE:-}" || -n "${SPHERES_BENCH_SETTLEMENT_START_FILE:-}" ]] ||
    die "SPHERES_BENCH_SETTLEMENT_FILE requires SPHERES_BENCH_SETTLEMENT_START_FILE"
metrics_url="${SPHERES_BENCH_METRICS_URL:-http://127.0.0.1:9201/metrics}"
# Optional prover-benchmark snapshot, after setup and before measured traffic.
snapshot_metrics_before() {
    [[ -n "${SPHERES_BENCH_METRICS_BEFORE_FILE:-}" ]] || return 0
    mkdir -p "$(dirname -- "$SPHERES_BENCH_METRICS_BEFORE_FILE")"
    curl --fail --silent --show-error "$metrics_url" >"$SPHERES_BENCH_METRICS_BEFORE_FILE"
    [[ -s "$SPHERES_BENCH_METRICS_BEFORE_FILE" ]] ||
        die "Sphere metrics were empty before the measured private flow"
}
if [[ -n "${SPHERES_BENCH_SETTLEMENT_START_FILE:-}" ]]; then
    # Fix the setup height before waiting; ongoing empty blocks cannot extend it.
    setup_tip="$(cast block-number --rpc-url "$SPHERE_RPC_URL")"
    [[ "$setup_tip" =~ ^[0-9]+$ ]] || die "could not read setup Sphere height"
    setup_deadline=$((SECONDS + ${SPHERES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS:-600}))
    while :; do
        setup_settled="$(read_l1_uint "$L1_PORTAL_ADDRESS" 'sphereHeight()(uint256)')"
        (( 10#$setup_settled >= 10#$setup_tip )) && break
        (( SECONDS < setup_deadline )) || die "setup Sphere height did not settle before measurement"
        sleep 1
    done
    mkdir -p "$(dirname -- "$SPHERES_BENCH_SETTLEMENT_START_FILE")"
    # Take the portal index, metrics, and start time together, retrying if a batch lands between
    # them, so every batch counted by the settlement delta is also in the metric delta.
    while :; do
        settlement_start_index="$(read_l1_uint "$L1_PORTAL_ADDRESS" 'withdrawalBatchIndex()(uint64)')"
        snapshot_metrics_before
        settlement_started_at="$(date +%s)"
        [[ "$(read_l1_uint "$L1_PORTAL_ADDRESS" 'withdrawalBatchIndex()(uint64)')" == "$settlement_start_index" ]] && break
        (( SECONDS < setup_deadline )) || die "portal batches kept landing during the start snapshot"
    done
else
    snapshot_metrics_before
fi
private_flow_parent_block="$(cast block-number --rpc-url "$SPHERE_RPC_URL")"
[[ "$private_flow_parent_block" =~ ^[0-9]+$ ]] ||
    die "could not read the Sphere head before the measured private flow"
if [[ -n "${SPHERES_BENCH_SETTLEMENT_START_FILE:-}" ]]; then
    jq -n --argjson batch_index "$settlement_start_index" --argjson timestamp "$settlement_started_at" \
        --argjson setup_tip "$setup_tip" --argjson setup_settled "$setup_settled" \
        '{batch_index:$batch_index,timestamp:$timestamp,setup_tip:$setup_tip,setup_settled:$setup_settled}' \
        >"$SPHERES_BENCH_SETTLEMENT_START_FILE"
fi
stage_start private_flow
scenario_report_args=()
build_scenario_report_args "$SPHERES_BENCH_REPORT"
"$txgen_bin" scenario run --scenario "$scenario_path" --count "$SPHERES_BENCH_COUNT" \
    --starts-per-second "$SPHERES_BENCH_TPS" --max-in-flight "$SPHERES_BENCH_MAX_CONCURRENT" --max-rpc-in-flight "$SPHERES_BENCH_MAX_CONCURRENT" \
    --failure-policy fail-fast --step-timeout "$SPHERES_BENCH_STEP_TIMEOUT" --seed "$SPHERES_BENCH_SEED" \
    --sample-instances "$sample_instances" "${scenario_report_args[@]}"
stage_end private_flow
private_flow_tip_block="$(cast block-number --rpc-url "$SPHERE_RPC_URL")"
[[ "$private_flow_tip_block" =~ ^[0-9]+$ ]] ||
    die "could not read the Sphere head after the measured private flow"
(( 10#$private_flow_tip_block > 10#$private_flow_parent_block )) ||
    die "the measured private flow produced no Sphere blocks"
mkdir -p "$(dirname "$SPHERES_BENCH_SPF_RANGE")"
{
    printf 'SPHERES_BENCH_SPF_FROM_BLOCK=%s\n' "$((10#$private_flow_parent_block + 1))"
    printf 'SPHERES_BENCH_SPF_TO_BLOCK=%s\n' "$((10#$private_flow_tip_block))"
} >"$SPHERES_BENCH_SPF_RANGE"
if [[ -n "${SPHERES_BENCH_SETTLEMENT_FILE:-}" ]]; then
    workload_done_at="$(date +%s)"
    settlement_deadline=$((SECONDS + 600))
    while :; do
        # Read both from one L1 block so the index and height describe the same portal state.
        l1_block="$(cast block-number --rpc-url "$L1_RPC_URL")"
        end_index="$(read_l1_uint "$L1_PORTAL_ADDRESS" 'withdrawalBatchIndex()(uint64)' --block "$l1_block")"
        settled_height="$(read_l1_uint "$L1_PORTAL_ADDRESS" 'sphereHeight()(uint256)' --block "$l1_block")"
        if (( 10#$end_index > 10#$settlement_start_index && 10#$settled_height >= 10#$private_flow_tip_block )); then
            settled_at="$(date +%s)"
            curl --fail --silent --show-error "$metrics_url" >"${SPHERES_BENCH_METRICS_AFTER_FILE:?}"
            [[ -s "$SPHERES_BENCH_METRICS_AFTER_FILE" ]] || die "empty metrics after settlement"
            jq -n --argjson before "$settlement_start_index" --argjson after "$end_index" \
                --argjson started_at "$(jq -er .timestamp "$SPHERES_BENCH_SETTLEMENT_START_FILE")" \
                --argjson workload_done_at "$workload_done_at" --argjson settled_at "$settled_at" \
                --argjson from "$((10#$private_flow_parent_block + 1))" \
                --argjson tip "$private_flow_tip_block" --argjson settled "$settled_height" \
                '{settled_batches:($after-$before),batch_index_before:$before,batch_index_after:$after,workload_from:$from,target_sphere_height:$tip,settled_sphere_height:$settled,started_at:$started_at,workload_done_at:$workload_done_at,settled_at:$settled_at}' \
                >"$SPHERES_BENCH_SETTLEMENT_FILE"
            break
        fi
        (( SECONDS < settlement_deadline )) || die "measured Sphere tip did not settle on L1"
        sleep 1
    done
fi
assert_scenario_report "$SPHERES_BENCH_REPORT" "$SPHERES_BENCH_COUNT" "private flow"
