"""Run the Arc/Sphere bridge steps from the verified USDC scenarios."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from local_rpc import L1, PRIVATE, SPHERE, USDC, rpc


PLAYGROUND = Path(__file__).resolve().parent
TXGEN = PLAYGROUND.parent / "txgen-sphere" / "target" / "debug" / "txgen-sphere"


def _run(operation, wallet, to, units):
    binary = Path(os.environ.get("TXGEN_BIN", TXGEN))
    if not binary.is_file():
        raise RuntimeError("Build txgen-sphere before starting a bridge operation.")
    with tempfile.TemporaryDirectory(prefix="sphere-bridge-") as directory:
        report = Path(directory) / "report.json"
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as auth:
            json.dump({wallet["address"].lower(): wallet["token"]}, auth)
        auth_map = Path(auth.name)
        env = {
            **os.environ,
            "L1_RPC_URL": L1,
            "L1_WS_RPC_URL": "ws://127.0.0.1:18550",
            "L1_PORTAL_ADDRESS": wallet["portal"],
            "SPHERE_RPC_URL": SPHERE,
            "SPHERE_WS_RPC_URL": "ws://127.0.0.1:18546",
            "SPHERE_REDACTED_RPC_URL": PRIVATE,
            "SPHERES_BENCH_EXPECTED_L1_CHAIN_ID": "1337",
            "SPHERES_BENCH_EXPECTED_SPHERE_CHAIN_ID": "5742371274753",
            "SPHERES_BENCH_EXPECTED_SPHERE_ID": "1",
            "SPHERES_BENCH_L1_QUERY_RPC_URL": L1,
            "SPHERES_BENCH_MNEMONIC": Path(wallet["mnemonic_file"]).read_text().strip(),
            "SPHERES_BENCH_ACCOUNT_START": str(wallet["index"]),
            "SPHERES_BENCH_ACCOUNT_END": str(wallet["index"] + 1),
            "SPHERES_BENCH_SPHERE_AUTH_MAP": str(auth_map),
            "SPHERES_BENCH_TOKEN": USDC,
            "SPHERES_BENCH_RECIPIENT": to.lower(),
            "SPHERES_BENCH_DEPOSIT_AMOUNT": str(units),
            "SPHERES_BENCH_WITHDRAWAL_AMOUNT": str(units),
            "SPHERES_BENCH_ACTIVITY_AMOUNT": "1",
            "SPHERES_BENCH_INBOX": "0x1c00000000000000000000000000000000000001",
            "SPHERES_BENCH_OUTBOX": "0x1c00000000000000000000000000000000000002",
            "SPHERES_BENCH_L1_MAX_FEE_PER_GAS": str(int(rpc(L1, "eth_gasPrice", []), 16)),
            "SPHERES_BENCH_SPHERE_MAX_FEE_PER_GAS": str(int(rpc(SPHERE, "eth_gasPrice", []), 16)),
            "SPHERES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS": "0",
            "SPHERES_BENCH_SPHERE_MAX_PRIORITY_FEE_PER_GAS": "0",
        }
        try:
            result = subprocess.run(
                [
                    str(binary), "scenario", "run",
                    "--scenario", str(PLAYGROUND / "scenarios" / f"{operation}.yml"),
                    "--count", "1", "--max-in-flight", "1", "--max-rpc-in-flight", "1",
                    "--step-timeout", "10m", "--sample-instances", "1",
                    "--failure-policy", "fail-fast", "--report", str(report),
                ],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=630,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Confirmation timed out. Check the wallet activity before retrying.") from None
        if not report.is_file():
            raise RuntimeError("The local transaction runner could not prepare the bridge operation.")
        data = json.loads(report.read_text())
        if result.returncode or data["completed"] != 1 or data["failed"] or data["timed_out"]:
            failure = next(iter(data["failures"]), {})
            step = failure.get("step_name", operation)
            classification = failure.get("classification", "unconfirmed")
            raise RuntimeError(f"Bridge step {step} was unsuccessful ({classification}).")
        return {
            step["id"]: step["milestones"][-1]
            for step in data["sampled_instances"][0]["steps"] if step.get("milestones")
        }


def deposit(wallet, to, units):
    steps = _run("deposit", wallet, to, units)
    escrow = steps["onramp.enqueued"]
    credit = steps["onramp.sphere_deposit.processed"]
    return {
        "hash": escrow["transaction_hash"], "chain": "arc", "blockNumber": escrow["block_number"],
        "status": "confirmed", "depositHash": escrow["transaction_hash"],
        "creditHash": credit["transaction_hash"], "creditBlockNumber": credit["block_number"],
    }


def withdraw(wallet, to, units):
    steps = _run("withdraw", wallet, to, units)
    request = steps["offramp_result"]
    settlement = steps["offramp_settled"]
    payout = steps["offramp_processed"]
    return {
        "hash": request["transaction_hash"], "chain": "sphere", "blockNumber": request["block_number"],
        "status": "confirmed", "withdrawalHash": request["transaction_hash"],
        "settlementHash": settlement["transaction_hash"],
        "payoutHash": payout["transaction_hash"], "payoutBlockNumber": payout["block_number"],
    }
