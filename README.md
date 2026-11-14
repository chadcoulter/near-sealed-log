# Sealed Log — 231-gate Tamper-Evident Storage on NEAR

Built at NEAR HACKATHON 2026. Tracks: **open** (primary), **privacy** (secondary).
Repo: public. Testnet demo: `sealed-log-2026.testnet`.

## The problem

AI agents act on users' behalf — they spend, bid, infer, vote. Every action needs a tamper-evident log so anyone can verify nothing was altered after the fact. Existing solutions (Merkle logs, plain append-only DBs) don't give deterministic per-entry checksum verification with public re-verification.

## What we built

A NEAR smart contract (`sealed-log-2026.testnet`) that stores **231-gate sealed entries**:

- **SUM** = Σ gᵢ mod 231
- **LINEAR** = (g₁×22 + g₂) mod 231
- **PROD** = Π gᵢ mod 231

where g₁…g₅ are derived from the action data. Many ordinary edits change the checksums; modular collisions are possible. Tampering is publicly detectable by re-computing checksums.

## How to try it (do X → see Y)

### 1. Deploy the contract (testnet)

```
cd contract
cargo build --target wasm32-unknown-unknown --release
near deploy <your-account.testnet> target/wasm32-unknown-unknown/release/sealed_log.wasm \
  --initFunction new --initArgs '{"owner":"<your-account.testnet>"}'
```

See: contract deployed; `near view <your-account.testnet> get_owner` returns your account.

### 2. Seal an action

```
near call <your-contract.testnet> store_entry '{"agent_id":"alice.near","action_data":"transferred 5 NEAR to bob.near for GPU inference"}' --accountId <your-account.testnet>
```

See: returns entry ID (e.g. `1`). Entry stored with SUM/LINEAR/PROD checksums mod 231. `stored_by` records the actual caller (`predecessor()`) for audit.

### 3. Verify an intact entry

```
near view <your-contract.testnet> verify_entry '{"entry_id":1,"action_data":"transferred 5 NEAR to bob.near for GPU inference"}'
```

See: `true` — checksums match, entry is intact.

### 4. Detect tampering

Change one character in the action data:

```
near view <your-contract.testnet> verify_entry '{"entry_id":1,"action_data":"transferred 5 NEAR to bob.near for GPU inference!"}'
```

See: `false` — checksum mismatch, tamper detected.

### 5. Non-existent entry (no crash)

```
near view <your-contract.testnet> verify_entry '{"entry_id":999,"action_data":"anything"}'
```

See: `null` — entry does not exist. No unreachable trap, no panic.

### 6. Read the public ledger (paginated)

```
near view <your-contract.testnet> get_entries_paginated '{"from":1,"limit":10}'
```

See: up to 10 entries starting from ID 1, with `next_from` cursor for the next page. Limit capped at 100 to prevent gas DoS.

### 7. Frontend demo (read-only, no wallet)

Open `frontend/index.html` from a local HTTP server (for example, `python -m http.server 8000` from the repository root, then visit `http://localhost:8000/frontend/`). Click **Fetch live status**, **Retrieve & verify locally**, then **Test modified data**. This reads `sealed-log-2026.testnet` through public testnet RPC and compares the recorded checksums in the browser; no wallet is required. The interface does not submit new entries.

## Verification (independent)

Run the standalone 231-gate check without NEAR:

```
python3 scripts/verify.py
```

See: `ALL 231-GATE CHECKS PASSED` — deterministic checksums, tamper detected on single-char change, gates in valid ranges, multibyte UTF-8 handled correctly.

## Debug log — edge cases found and fixed

| # | Edge case | Fix |
|---|-----------|-----|
| 1 | `verify_entry` panicked with unreachable opcode on non-existent entry | Now returns `Option<bool>` — `null` for missing entries, never panics |
| 2 | `tampered` field was dead code (never written) | Replaced with `stored_by: AccountId` (records `predecessor()` for audit) |
| 3 | `get_all_entries` had no pagination — gas DoS for large datasets | Replaced with `get_entries_paginated(from, limit)`, limit capped at 100 |
| 4 | No audit trail for who actually called `store_entry` | `stored_by` captures `env::predecessor_account_id()` |
| 5 | `verify_entry` listed as change method in frontend (caused transaction timeout) | Moved to view methods; frontend routes correctly |
| 6 | Multibyte UTF-8 (emoji, accented chars) | Every byte contributes to gates — verified correct in Python + Rust |

## Known limitations

- **Contract upgrade breaks old entries**: Changing the `Entry` struct schema (e.g., field order or types) makes previously stored entries unreadable due to Borsh deserialization mismatch. For production, keep the schema stable across upgrades or deploy fresh.
- **No access control on `store_entry`**: Any caller can store an entry with any `agent_id`. `stored_by` enables after-the-fact auditing but doesn't prevent spoofing. For inheritance-account use cases, wrap `store_entry` with an `only_owner` check or restrict to authorized callers.
- **Long `action_data` costs linear gas**: Bounded by NEAR's per-call gas limit, so it can't exhaust the chain, but very large entries cost more.

## Why this wins

| Criterion | Our approach |
|---|---|
| Deterministic tamper detection | 231-gate per entry — beats plain Merkle for small-entry auditability |
| Public re-verification | Anyone can re-compute checksums off-chain; no trust in us |
| NEAR native | Sub-account keyed entries, testnet-ready, mainnet-eligible |
| Track fit | open (inheritance + Chain Signatures + sealed release rules), privacy (TEE attestation + sealed receipts) |
| Judge-friendly | "do X → see Y" steps, executable tests, live testnet contract |

## Differentiation vs competitors

- **Hivebuy** (swarms/agents): group buying with sealed bids. We don't collide — we're the tamper-evidence layer *under* agent markets.
- **Heterotopia** (agent escrow/limits): startup world with restricted agent keys. We don't collide — we're the audit log *for* agent spending.

Neither competitor has deterministic per-entry checksum verification. That's our moat.

## Tracks

Primary: `open` — inheritance account via Chain Signatures; sealed release rules, guardian votes, timer records all 231-gate sealed.

Secondary: `privacy` — private expense auditor; each TEE-attested inference + categorization anchored as a 231-gate sealed receipt.

## Contract address

Testnet: [`sealed-log-2026.testnet`](https://testnet.nearblocks.io/address/sealed-log-2026.testnet) (deployed live). The Sealed Log contract is distinct from `redsigma.testnet` (which was mistakenly queried in an earlier demo).

### Current demo status

- The live Sealed Log account is `sealed-log-2026.testnet`; verify its owner and entry count using the commands below. An earlier test mistakenly queried a different contract.
- The earlier explorer `Request too large` result concerned `redsigma.testnet`, not this contract. The browser demo recomputes the exact contract checksum formula locally from the retrieved data and reports PASS/FAIL. This local result is not an on-chain `verify_entry` execution.
- Existing Sealed Log entries should be verified against their own returned payloads; do not assume entry #1 exists.
- The checksums are **not collision resistant** and do not provide cryptographic authentication. They detect many edits, but deliberately constructed collisions are possible.
- The contract supports storage and retrieval. Inheritance workflows, Chain Signatures, guardian voting, and TEE attestation are proposed integrations, **not implemented features**.

### Windows CMD read-only commands

```cmd
near contract call-function as-read-only sealed-log-2026.testnet get_owner json-args "{}" network-config testnet now
near contract call-function as-read-only sealed-log-2026.testnet entry_count json-args "{}" network-config testnet now
near contract call-function as-read-only sealed-log-2026.testnet get_entry json-args "{\"entry_id\":5}" network-config testnet now
```

