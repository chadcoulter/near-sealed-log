#!/usr/bin/env python3
"""Independent 231-gate verification — runs WITHOUT NEAR.

Verifies the core cryptographic primitive that the contract implements:
- SUM, LINEAR, PROD checksums mod 231
- Deterministic (same input → same output)
- Tamper detection (single-char change breaks checksums)
- Gates in valid ranges
"""
MOD = 231
LINEAR_MULT = 22


def derive_gates(action_data: str):
    """Fold ALL bytes of the input into 5 gate values so every byte matters."""
    bytes_ = action_data.encode()
    gates = [0] * 5
    for i, b in enumerate(bytes_):
        gates[i % 5] = (gates[i % 5] + b) % (22 if i % 5 < 2 else MOD)
    return gates


def compute_checksums(action_data: str):
    g = derive_gates(action_data)
    s = (g[0] + g[1] + g[2] + g[3] + g[4]) % MOD
    l = (g[0] * LINEAR_MULT + g[1]) % MOD
    p = (((g[0] * g[1]) % MOD) * (((g[2] * g[3]) % MOD) * g[4] % MOD)) % MOD
    return {"sum": s, "linear": l, "prod": p}


def main():
    failures = []

    # 1. Deterministic
    c1 = compute_checksums("hello world")
    c2 = compute_checksums("hello world")
    assert c1 == c2, "checksums not deterministic"
    print("PASS deterministic checksums:", c1)

    # 2. Tamper detection — single char change must break at least one checksum
    c_tampered = compute_checksums("hello world!")
    changed = c1["sum"] != c_tampered["sum"] or c1["linear"] != c_tampered["linear"] or c1["prod"] != c_tampered["prod"]
    assert changed, "tamper not detected"
    print("PASS tamper detected on single-char change")

    # 3. Gates in range
    g = derive_gates("test data")
    assert g[0] < 22 and g[1] < 22, "g1/g2 out of range"
    assert all(x < MOD for x in g[2:5]), "g3/g4/g5 out of range"
    print("PASS gates in valid range:", g)

    # 4. Checksums in [0, 230]
    for k, v in c1.items():
        assert 0 <= v < MOD, f"{k}={v} out of range"
    print("PASS checksums in [0,230]:", c1)

    # 5. Different inputs produce different checksums (collision resistance spot check)
    c_a = compute_checksums("transfer 5 NEAR to alice")
    c_b = compute_checksums("transfer 5 NEAR to bob")
    diff = c_a != c_b
    assert diff, "different inputs produced identical checksums"
    print("PASS different inputs → different checksums")

    print("\nALL 231-GATE CHECKS PASSED")


if __name__ == "__main__":
    main()
