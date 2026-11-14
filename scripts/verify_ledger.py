#!/usr/bin/env python3
"""Independent on-chain ledger verification for the Sealed Log contract.

Reads the public ledger straight from NEAR testnet RPC (no near-cli, no
contract SDK) and re-computes the 231-gate checksums with the standalone
algorithm in verify.py, then compares against what the contract stored.

Exit code 0 = every entry's stored checksums match the independently
computed ones. Non-zero = at least one mismatch.
"""
import base64
import json
import sys
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from verify import compute_checksums  # noqa: E402

RPC = "https://rpc.testnet.near.org"
CONTRACT = "sealed-log-2026.testnet"


def rpc_call(method, args):
    payload = {
        "jsonrpc": "2.0",
        "id": "sealed-log-verify",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "account_id": CONTRACT,
            "method_name": method,
            "args_base64": base64.b64encode(json.dumps(args).encode()).decode(),
            "finality": "final",
        },
    }
    req = urllib.request.Request(
        RPC,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.load(resp)
    if "error" in body:
        raise RuntimeError(body["error"])
    raw = body["result"]["result"]
    return json.loads(bytes(raw).decode())


def main():
    page = rpc_call("get_entries_paginated", {"from": 1, "limit": 100})
    entries = page["entries"]
    print(f"contract={CONTRACT} entries={len(entries)} next_from={page['next_from']}")

    failures = []
    for e in entries:
        computed = compute_checksums(e["action_data"])
        stored = e["checksums"]
        ok = all(stored[k] == computed[k] for k in ("sum", "linear", "prod"))
        status = "PASS" if ok else "FAIL"
        print(
            f"  [{status}] #{e['entry_id']} agent={e['agent_id']} "
            f"stored_by={e['stored_by']} "
            f"stored={stored} computed={computed}"
        )
        if not ok:
            failures.append(e["entry_id"])

    # Tamper check on the first entry: the contract must reject a one-byte edit.
    if entries:
        e = entries[0]
        intact = rpc_call(
            "verify_entry", {"entry_id": e["entry_id"], "action_data": e["action_data"]}
        )
        tampered = rpc_call(
            "verify_entry",
            {"entry_id": e["entry_id"], "action_data": e["action_data"] + "!"},
        )
        print(f"  verify_entry(#{e['entry_id']}, intact)   = {intact}")
        print(f"  verify_entry(#{e['entry_id']}, tampered) = {tampered}")
        if intact is not True or tampered is not False:
            failures.append(f"verify_entry #{e['entry_id']}")

    if failures:
        print(f"\nLEDGER VERIFICATION FAILED: {failures}")
        return 1
    print("\nLEDGER VERIFICATION PASSED — all stored checksums match independent recomputation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
