"""Loopback API for the fixed local Arc / Sphere #1 demo."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from urllib.parse import parse_qs, urlsplit
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import time

from local_rpc import L1, PRIVATE, SPHERE, USDC, cast, rpc

ARC_ID, SPHERE_ID = 1337, (1337 << 32) | 1
DEMO_INDICES = (2, 3)
FRONTEND = "http://127.0.0.1:15151"
HOSTS = {"127.0.0.1:15151", "127.0.0.1:15152"}
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
AMOUNT = re.compile(r"(0|[1-9][0-9]{0,32})(?:\.([0-9]{1,6}))?\Z")
TXGEN = Path(__file__).resolve().parents[1] / "txgen-sphere/target/debug/txgen-sphere"


def amount_units(value):
    match = AMOUNT.fullmatch(value) if isinstance(value, str) else None
    if match:
        units = int(match[1]) * 1_000_000 + int((match[2] or "").ljust(6, "0"))
        if 0 < units < 1 << 128:
            return units
    raise ValueError("Enter a positive USDC amount with up to six decimal places.")


def usdc_balance(url, address, token=None):
    calldata = cast("calldata", "balanceOf(address)", address)
    data = rpc(url, "eth_call", [{"from": address, "to": USDC, "data": calldata}, "latest"], token)
    return int(data, 16)


def validate_chains(token):
    for url, expected in ((L1, ARC_ID), (SPHERE, SPHERE_ID), (PRIVATE, SPHERE_ID)):
        if int(rpc(url, "eth_chainId", [], token if url == PRIVATE else None), 16) != expected:
            raise RuntimeError("The local node has the wrong chain ID.")


def receipt(wallet, chain, tx_hash):
    if chain not in ("arc", "sphere") or not TX_HASH.fullmatch(tx_hash):
        raise ValueError("Invalid chain or transaction hash.")
    tx = (rpc(L1, "eth_getTransactionReceipt", [tx_hash]) if chain == "arc" else
          rpc(PRIVATE, "eth_getTransactionReceipt", [tx_hash], wallet["token"]))
    result = {"chain": chain, "hash": tx_hash, "blockNumber": None, "status": "pending"}
    if tx:
        if tx["from"].lower() != wallet["address"] or tx["transactionHash"].lower() != tx_hash.lower():
            raise ValueError("The receipt does not belong to the selected sender.")
        result.update(blockNumber=int(tx["blockNumber"], 16),
                      status="confirmed" if int(tx["status"], 16) == 1 else "reverted")
    return result


def payment(wallet, to, units):
    account, token = wallet["address"], wallet["token"]
    if usdc_balance(PRIVATE, account, token) < units:
        raise ValueError("Insufficient Sphere USDC for this payment.")
    data = cast("calldata", "transfer(address,uint256)", to, units)
    nonce = int(rpc(PRIVATE, "eth_getTransactionCount", [account, "pending"], token), 16)
    gas_price = int(rpc(SPHERE, "eth_gasPrice", []), 16)
    raw = cast("mktx", USDC, data, "--rpc-url", PRIVATE, "--chain", SPHERE_ID,
               "--nonce", nonce, "--gas-limit", 500000, "--gas-price", gas_price,
               "--priority-gas-price", 0, "--mnemonic", wallet["mnemonic_file"],
               "--mnemonic-index", wallet["index"])
    tx_hash = rpc(PRIVATE, "eth_sendRawTransaction", [raw], token)
    deadline = time.monotonic() + 45
    while True:
        result = receipt(wallet, "sphere", tx_hash)
        if result["status"] != "pending" or time.monotonic() >= deadline:
            return result
        time.sleep(0.3)


class LocalWallets:
    def __init__(self):
        self.mnemonic = Path(os.environ["SPHERES_BENCH_MNEMONIC_FILE"])
        info = self.mnemonic.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("The local wallet mnemonic must be an owner-only regular file.")
        self.portal = os.environ["L1_PORTAL_ADDRESS"].lower()
        if not ADDRESS.fullmatch(self.portal):
            raise ValueError("Invalid local portal address.")
        if cast("call", self.portal, "sphereId()(uint32)", "--rpc-url", L1) != "1":
            raise ValueError("Expected local Sphere #1 portal.")
        factory = cast("call", self.portal, "sphereFactory()(address)", "--rpc-url", L1)
        if cast("call", factory, "isSpherePortal(address)(bool)", self.portal, "--rpc-url", L1) != "true":
            raise ValueError("The local factory does not recognize this portal.")
        self.indices = {cast("wallet", "address", "--mnemonic", self.mnemonic, "--mnemonic-index", i).lower(): i
                        for i in DEMO_INDICES}
        self.lock = Lock()
        self.tokens = {}
        self.refresh_at = 0
        validate_chains(self.wallet(next(iter(self.indices)))["token"])

    def wallet(self, address):
        if not isinstance(address, str) or address.lower() not in self.indices:
            raise ValueError("Choose one of the local demo wallets.")
        address = address.lower()
        with self.lock:
            if time.monotonic() >= self.refresh_at:
                # Same auth-token-map command and pool semantics as run-neobank-private-flow.sh.
                with TemporaryDirectory() as directory:
                    spec = Path(directory) / "accounts.json"
                    output = Path(directory) / "tokens.json"
                    spec.write_text(json.dumps({"chain_id": SPHERE_ID, "accounts": {"users": {
                        "mnemonic": "${SPHERES_BENCH_MNEMONIC}", "range": [min(DEMO_INDICES), max(DEMO_INDICES) + 1]}}}))
                    subprocess.run([os.environ.get("TXGEN_BIN", str(TXGEN)), "auth-token-map",
                                    "--spec", spec, "--pool", "users", "--sphere-id", "1",
                                    "--chain-id", str(SPHERE_ID), "--ttl-secs", "1800", "--output", output],
                                   env={**os.environ, "SPHERES_BENCH_MNEMONIC": self.mnemonic.read_text().strip()},
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
                    tokens = json.loads(output.read_text())
                    if tokens.keys() != self.indices.keys():
                        raise RuntimeError("The auth map did not match the two demo accounts.")
                    self.tokens = tokens
                    self.refresh_at = time.monotonic() + 900
            return {"address": address, "index": self.indices[address], "token": self.tokens[address],
                    "mnemonic_file": str(self.mnemonic), "portal": self.portal}


class Handler(BaseHTTPRequestHandler):
    def answer(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.handle_api(False)

    def do_POST(self):
        self.handle_api(True)

    def handle_api(self, write):
        origin = self.headers.get("Origin")
        if self.headers.get("Host") not in HOSTS or origin not in (None, FRONTEND):
            return self.answer(403, {"error": "Unrecognized playground origin."})
        if write and (origin != FRONTEND or not hmac.compare_digest(
                self.headers.get("X-CSRF-Token", "").encode(), self.server.csrf.encode())):
            return self.answer(403, {"error": "Refresh the page before submitting."})
        path = urlsplit(self.path)
        wallets = self.server.wallets
        try:
            if not write and path.path == "/api/accounts":
                result = []
                for address in wallets.indices:
                    wallet = wallets.wallet(address)
                    result.append({"address": address, "arcBalance": str(usdc_balance(L1, address)),
                                   "sphereBalance": str(usdc_balance(PRIVATE, address, wallet["token"]))})
                return self.answer(200, {"accounts": result, "csrfToken": self.server.csrf})
            if not write and path.path == "/api/receipt":
                args = parse_qs(path.query)
                return self.answer(200, receipt(wallets.wallet(args["from"][0]), args["chain"][0], args["hash"][0]))
            if not write or path.path not in ("/api/payment", "/api/deposit", "/api/withdraw"):
                return self.answer(404, {"error": "Unknown playground route."})
            if self.headers.get_content_type() != "application/json":
                return self.answer(415, {"error": "Send a JSON request."})
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 2048:
                return self.answer(400, {"error": "Invalid request size."})
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict) or set(body) != {"from", "to", "amount"}:
                return self.answer(400, {"error": "Expected from, to, and amount."})
            wallet = wallets.wallet(body["from"])
            recipient = body["to"]
            if not isinstance(recipient, str) or not ADDRESS.fullmatch(recipient) or int(recipient, 16) == 0:
                raise ValueError("Enter a nonzero 0x recipient address with 40 hexadecimal digits.")
            recipient = recipient.lower()
            units = amount_units(body["amount"])
            if not self.server.writing.acquire(blocking=False):
                return self.answer(409, {"error": "A local transaction is already in progress."})
            try:
                validate_chains(wallet["token"])
                if path.path == "/api/payment":
                    result = payment(wallet, recipient, units)
                else:
                    from bridge_operations import deposit, withdraw
                    result = (deposit if path.path == "/api/deposit" else withdraw)(wallet, recipient, units)
            finally:
                self.server.writing.release()
            self.answer(200, result)
        except (KeyError, UnicodeError, json.JSONDecodeError):
            self.answer(400, {"error": "Invalid request parameters."})
        except ValueError as error:
            self.answer(400, {"error": str(error)})
        except RuntimeError as error:
            self.answer(502, {"error": str(error)})
        except (OSError, subprocess.SubprocessError):
            self.answer(503, {"error": "The local payment service is unavailable."})


if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", 15152), Handler) as server:
        server.wallets = LocalWallets()
        server.csrf = secrets.token_urlsafe(32)
        server.writing = Lock()
        server.serve_forever()
