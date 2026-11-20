#!/usr/bin/env bash

# Build txgen scenario reporter arguments without placing ClickHouse credentials
# in argv. The endpoint is credential-free; authentication stays in txgen's
# CLICKHOUSE_USER and CLICKHOUSE_PASSWORD environment variables.
build_scenario_report_args() {
    local json_report="$1"
    local name pair metadata_name environment_name
    local -a configuration_metadata=(
        "accounts:SPHERES_BENCH_ACCOUNTS"
        "count:SPHERES_BENCH_COUNT"
        "target-rate:SPHERES_BENCH_TPS"
        "max-concurrent:SPHERES_BENCH_MAX_CONCURRENT"
        "deposit-amount:SPHERES_BENCH_DEPOSIT_AMOUNT"
        "activity-amount:SPHERES_BENCH_ACTIVITY_AMOUNT"
        "withdrawal-amount:SPHERES_BENCH_WITHDRAWAL_AMOUNT"
        "l1-gas-limit:SPHERES_BENCH_L1_GAS_LIMIT"
        "l1-general-gas-limit:SPHERES_BENCH_L1_GENERAL_GAS_LIMIT"
        "sphere-gas-limit:SPHERES_BENCH_SPHERE_GAS_LIMIT"
        "withdrawal-max-batch-gas:SPHERES_BENCH_WITHDRAWAL_MAX_BATCH_GAS"
        "withdrawal-max-in-flight-batches:SPHERES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES"
        "sphere-batch-interval-blocks:SPHERES_BENCH_SPHERE_BATCH_INTERVAL_BLOCKS"
        "withdrawal-poll-interval-secs:SPHERES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS"
        "step-timeout:SPHERES_BENCH_STEP_TIMEOUT"
        "setup-settlement-timeout-secs:SPHERES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS"
        "drain-timeout-secs:SPHERES_BENCH_DRAIN_TIMEOUT"
        "seed:SPHERES_BENCH_SEED"
        "force-bloat:SPHERES_BENCH_FORCE_BLOAT"
        "arc-hardfork:SPHERES_BENCH_ARC_HARDFORK"
        "arc-revision:SPHERES_BENCH_ARC_REF"
        "txgen-revision:SPHERES_BENCH_TXGEN_REF"
    )

    scenario_report_args=(--report "$json_report")
    if [[ -z "${CLICKHOUSE_URL:-}" ]]; then
        if [[ "${SPHERES_BENCH_REQUIRE_CLICKHOUSE:-0}" == 1 ]]; then
            echo "error: CLICKHOUSE_URL is required for this benchmark run" >&2
            return 1
        fi
        return 0
    fi

    for name in \
        CLICKHOUSE_USER CLICKHOUSE_PASSWORD \
        SPHERES_BENCH_SPHERES_REF SPHERES_BENCH_GIT_REF SPHERES_BENCH_PHASE \
        SPHERES_BENCH_NEOBANK_PRESET
    do
        if [[ -z "${!name:-}" ]]; then
            echo "error: $name is required when ClickHouse reporting is enabled" >&2
            return 1
        fi
    done

    scenario_report_args+=(
        --report "clickhouse:$CLICKHOUSE_URL"
        --metadata "git-sha=$SPHERES_BENCH_SPHERES_REF"
        --metadata "git-ref=$SPHERES_BENCH_GIT_REF"
        --metadata "phase=$SPHERES_BENCH_PHASE"
    )
    scenario_report_args+=(--metadata "neobank-preset=$SPHERES_BENCH_NEOBANK_PRESET")
    for pair in "${configuration_metadata[@]}"; do
        metadata_name="${pair%%:*}"
        environment_name="${pair#*:}"
        [[ -z "${!environment_name:-}" ]] ||
            scenario_report_args+=(--metadata "$metadata_name=${!environment_name}")
    done
    # Same labels as the prover benchmark's VictoriaMetrics series and the L1 nightlies.
    [[ -z "${SPHERES_BENCH_PROVER:-}" ]] ||
        scenario_report_args+=(--metadata "prover=$SPHERES_BENCH_PROVER")
    [[ -z "${SPHERES_BENCH_RUN_TYPE:-}" ]] ||
        scenario_report_args+=(--metadata "run_type=$SPHERES_BENCH_RUN_TYPE")
    [[ -z "${SPHERES_BENCH_RUN_ID:-}" ]] ||
        scenario_report_args+=(--metadata "spheres-run-id=$SPHERES_BENCH_RUN_ID")
    [[ -z "${SPHERES_BENCH_BLOAT_GIB:-}" ]] ||
        scenario_report_args+=(--metadata "state-bloat-gib=$SPHERES_BENCH_BLOAT_GIB")
    [[ -z "${SPHERES_BENCH_GITHUB_REPOSITORY:-}" ]] ||
        scenario_report_args+=(--metadata "github-repository=$SPHERES_BENCH_GITHUB_REPOSITORY")
    [[ -z "${SPHERES_BENCH_GITHUB_RUN_ID:-}" ]] ||
        scenario_report_args+=(--metadata "github-run-id=$SPHERES_BENCH_GITHUB_RUN_ID")
    [[ -z "${SPHERES_BENCH_GITHUB_WORKFLOW:-}" ]] ||
        scenario_report_args+=(--metadata "github-workflow-file=$SPHERES_BENCH_GITHUB_WORKFLOW")
    [[ -z "${SPHERES_BENCH_GITHUB_PR_NUMBER:-}" ]] ||
        scenario_report_args+=(--metadata "github-pr-number=$SPHERES_BENCH_GITHUB_PR_NUMBER")
}
