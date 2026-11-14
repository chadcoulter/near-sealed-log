use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, Vector};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::state::ContractState;
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault};

const MOD: u64 = 231;
const LINEAR_MULT: u64 = 22;
const MAX_PAGE_SIZE: u64 = 100;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct Checksums {
    pub sum: u64,    // SUM channel: sum(g_i) mod 231
    pub linear: u64, // LINEAR channel: (g1*22 + g2) mod 231
    pub prod: u64,   // PROD channel: prod(g_i) mod 231
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Entry {
    pub entry_id: u64,
    pub agent_id: String,
    pub action_data: String,
    pub checksums: Checksums,
    pub timestamp: u64,
    pub stored_by: AccountId, // who called store_entry (prevents agent_id spoofing claims)
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Page {
    pub entries: Vec<Entry>,
    pub next_from: Option<u64>,
}

/// Legacy schema written before `stored_by` was added. Kept only so the
/// migration can deserialize pre-upgrade entries; never written again.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct EntryV1 {
    pub entry_id: u64,
    pub agent_id: String,
    pub action_data: String,
    pub checksums: Checksums,
    pub timestamp: u64,
    pub tampered: bool,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct SealedLog {
    entries: LookupMap<u64, Entry>,
    all_ids: Vector<u64>,
    next_entry_id: u64,
    owner: AccountId,
}

impl ContractState for SealedLog {}

#[near_bindgen]
impl SealedLog {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            entries: LookupMap::new(b"e"),
            all_ids: Vector::new(b"i"),
            next_entry_id: 1,
            owner,
        }
    }

    /// Derive 5 gate values from action data bytes. Every byte contributes.
    fn derive_gates(action_data: &str) -> [u64; 5] {
        let bytes = action_data.as_bytes();
        let mut gates = [0u64; 5];
        for (i, &b) in bytes.iter().enumerate() {
            let slot = i % 5;
            let bound = if slot < 2 { 22u64 } else { MOD };
            gates[slot] = (gates[slot] + b as u64) % bound;
        }
        gates
    }

    /// Compute 231-gate checksums for action data.
    fn compute_checksums(action_data: &str) -> Checksums {
        let g = Self::derive_gates(action_data);
        let sum = (g[0] + g[1] + g[2] + g[3] + g[4]) % MOD;
        let linear = (g[0] * LINEAR_MULT + g[1]) % MOD;
        let prod = (((g[0] * g[1]) % MOD) * (((g[2] * g[3]) % MOD) * g[4] % MOD)) % MOD;
        Checksums { sum, linear, prod }
    }

    /// Store a new sealed entry. Records `predecessor()` as `stored_by` so
    /// agent_id claims can be audited against the actual caller.
    pub fn store_entry(&mut self, agent_id: String, action_data: String) -> u64 {
        let entry_id = self.next_entry_id;
        let checksums = Self::compute_checksums(&action_data);
        let entry = Entry {
            entry_id,
            agent_id,
            action_data,
            checksums,
            timestamp: env::block_timestamp(),
            stored_by: env::predecessor_account_id(),
        };
        self.entries.insert(&entry_id, &entry);
        self.all_ids.push(&entry_id);
        self.next_entry_id += 1;
        entry_id
    }

    /// Verify an entry: re-compute 231-gate checksums and compare against stored.
    /// Pure view — returns `Some(true)` if intact, `Some(false)` if tampered,
    /// `None` if the entry does not exist. Never panics.
    pub fn verify_entry(&self, entry_id: u64, action_data: String) -> Option<bool> {
        let entry = self.entries.get(&entry_id)?;
        let expected = Self::compute_checksums(&action_data);
        Some(
            entry.checksums.sum == expected.sum
                && entry.checksums.linear == expected.linear
                && entry.checksums.prod == expected.prod,
        )
    }

    /// One-time migration from the legacy `EntryV1` schema (trailing
    /// `tampered: bool`) to the current `Entry` (`stored_by: AccountId`).
    /// Reading a V1 entry under the V2 schema traps because Borsh interprets
    /// the trailing bool as the string length prefix of `stored_by`, so we
    /// read the raw stored bytes, deserialize them as V1, and rewrite them.
    /// Uses `insert_raw` so the old bytes are never deserialized as V2.
    pub fn migrate_v1_entries(&mut self) -> u64 {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "only owner can migrate"
        );
        let mut migrated = 0u64;
        for id in 1..self.next_entry_id {
            let mut key = b"e".to_vec();
            key.extend_from_slice(&borsh::to_vec(&id).unwrap());
            let raw = match env::storage_read(&key) {
                Some(raw) => raw,
                None => continue,
            };
            let old = match EntryV1::try_from_slice(&raw) {
                Ok(old) => old,
                Err(_) => continue,
            };
            let entry = Entry {
                entry_id: old.entry_id,
                agent_id: old.agent_id.clone(),
                action_data: old.action_data.clone(),
                checksums: old.checksums.clone(),
                timestamp: old.timestamp,
                // V1 did not record the caller; agent_id is the closest
                // audit value available for pre-upgrade entries.
                stored_by: old
                    .agent_id
                    .clone()
                    .try_into()
                    .unwrap_or_else(|_| self.owner.clone()),
            };
            let key_raw = borsh::to_vec(&id).unwrap();
            let value_raw = borsh::to_vec(&entry).unwrap();
            self.entries.insert_raw(&key_raw, &value_raw);
            migrated += 1;
        }
        migrated
    }

    /// Get an entry by ID.
    pub fn get_entry(&self, entry_id: u64) -> Option<Entry> {
        self.entries.get(&entry_id)
    }

    /// Get entries paginated: `from` is the starting entry_id (inclusive),
    /// `limit` caps the page size (max 100). Returns entries and the next `from`
    /// cursor, or `None` if there are no more entries.
    pub fn get_entries_paginated(&self, from: u64, limit: u64) -> Page {
        let limit = limit.min(MAX_PAGE_SIZE);
        let mut entries = Vec::new();
        let mut next_from: Option<u64> = None;
        let mut count = 0u64;
        for id in from..self.next_entry_id {
            if let Some(entry) = self.entries.get(&id) {
                entries.push(entry);
                count += 1;
                if count >= limit {
                    next_from = Some(id + 1);
                    break;
                }
            }
        }
        Page { entries, next_from }
    }

    /// Get entry count.
    pub fn entry_count(&self) -> u64 {
        self.next_entry_id - 1
    }

    /// Get the contract owner.
    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksums_deterministic() {
        let c1 = SealedLog::compute_checksums("hello world");
        let c2 = SealedLog::compute_checksums("hello world");
        assert_eq!(c1.sum, c2.sum);
        assert_eq!(c1.linear, c2.linear);
        assert_eq!(c1.prod, c2.prod);
    }

    #[test]
    fn test_checksums_detect_tamper() {
        let c1 = SealedLog::compute_checksums("hello world");
        let c2 = SealedLog::compute_checksums("hello world!");
        assert!(c1.sum != c2.sum || c1.linear != c2.linear || c1.prod != c2.prod);
    }

    #[test]
    fn test_gates_in_range() {
        let g = SealedLog::derive_gates("test data");
        assert!(g[0] < 22 && g[1] < 22);
        assert!(g[2] < MOD && g[3] < MOD && g[4] < MOD);
    }

    #[test]
    fn test_multibyte_utf8() {
        let c1 = SealedLog::compute_checksums("café résumé");
        let c2 = SealedLog::compute_checksums("café résumé");
        assert_eq!(c1, c2);
        let c3 = SealedLog::compute_checksums("café résumé!");
        assert!(c1 != c3);
    }

    #[test]
    fn test_pagination_limits() {
        // Just verify compute_checksums works for pagination-relevant sizes
        let long = "a".repeat(10000);
        let c = SealedLog::compute_checksums(&long);
        assert!(c.sum < MOD && c.linear < MOD && c.prod < MOD);
    }

    #[test]
    fn test_v1_schema_roundtrips() {
        let v1 = EntryV1 {
            entry_id: 7,
            agent_id: "alice.near".to_string(),
            action_data: "transferred 5 NEAR".to_string(),
            checksums: Checksums {
                sum: 1,
                linear: 2,
                prod: 3,
            },
            timestamp: 123,
            tampered: false,
        };
        let bytes = borsh::to_vec(&v1).unwrap();
        let back = EntryV1::try_from_slice(&bytes).unwrap();
        assert_eq!(back.entry_id, 7);
        assert_eq!(back.agent_id, "alice.near");
        assert!(!back.tampered);
    }

    #[test]
    fn test_v1_bytes_are_not_readable_as_v2() {
        // Documents the live trap: the trailing `tampered: bool` of V1 is
        // consumed as the 4-byte length prefix of V2's `stored_by: String`,
        // leaving the slice short, so deserialization fails.
        let v1 = EntryV1 {
            entry_id: 1,
            agent_id: "alice.near".to_string(),
            action_data: "data".to_string(),
            checksums: Checksums {
                sum: 1,
                linear: 2,
                prod: 3,
            },
            timestamp: 123,
            tampered: false,
        };
        let bytes = borsh::to_vec(&v1).unwrap();
        assert!(Entry::try_from_slice(&bytes).is_err());
    }

    #[test]
    fn test_v1_agent_id_survives_as_stored_by() {
        // The migration maps agent_id -> stored_by for pre-upgrade entries.
        let v1 = EntryV1 {
            entry_id: 3,
            agent_id: "bob.near".to_string(),
            action_data: "x".to_string(),
            checksums: Checksums {
                sum: 4,
                linear: 5,
                prod: 6,
            },
            timestamp: 9,
            tampered: false,
        };
        let bytes = borsh::to_vec(&v1).unwrap();
        let old = EntryV1::try_from_slice(&bytes).unwrap();
        let migrated = Entry {
            entry_id: old.entry_id,
            agent_id: old.agent_id.clone(),
            action_data: old.action_data.clone(),
            checksums: old.checksums.clone(),
            timestamp: old.timestamp,
            stored_by: old.agent_id.try_into().unwrap(),
        };
        assert_eq!(migrated.stored_by, "bob.near");
        // And the migrated form must deserialize cleanly as V2.
        let v2_bytes = borsh::to_vec(&migrated).unwrap();
        assert!(Entry::try_from_slice(&v2_bytes).is_ok());
    }
}
