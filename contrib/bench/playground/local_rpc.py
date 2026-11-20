"""Local JSON-RPC and cast transports used by the playground payment and bridge routes."""
import http.client
import json
import os
import subprocess

L1 = "http://127.0.0.1:18549"
SPHERE = "http://127.0.0.1:18545"
PRIVATE = "http://127.0.0.1:18544"
USDC = "0x3600000000000000000000000000000000000000"
PORTS = {L1: 18549, SPHERE: 18545, PRIVATE: 18544}


def rpc(url, method, params, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        if url != PRIVATE:
            raise ValueError("A private token requires the redacted Sphere endpoint.")
        headers["X-Authorization-Token"] = token
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    conn = http.client.HTTPConnection("127.0.0.1", PORTS[url], timeout=15)
    try:
        conn.request("POST", "/", body, headers)
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError(f"{method} returned HTTP {response.status}.")
        reply = json.loads(response.read())
        if "error" in reply:
            raise RuntimeError(f"{method} failed (RPC {reply['error']['code']}).")
        return reply["result"]
    finally:
        conn.close()


def cast(*args, timeout=60, env=None):
    result = subprocess.run(["cast", *map(str, args)], capture_output=True, text=True,
                            timeout=timeout, env=os.environ if env is None else env)
    if result.returncode:
        raise RuntimeError(f"cast {args[0]} failed.")
    return result.stdout.strip()
