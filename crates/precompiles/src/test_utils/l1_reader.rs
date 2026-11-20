//! Shared L1 reader fixtures for precompile and EVM integration tests.
use crate::{L1StateError, L1StorageReader};
use alloy_primitives::{Address, B256, U256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
pub type L1Slot = (Address, B256, u64);
type Shared<T> = Arc<Mutex<T>>;

/// In-memory exact-block L1 reader shared by EVM and precompile tests.
#[derive(Clone)]
pub struct MockL1Reader {
    slots: Shared<HashMap<L1Slot, B256>>,
    storage_requests: Shared<Vec<L1Slot>>,
    fallback: B256,
    fail_storage: bool,
}

impl Default for MockL1Reader {
    fn default() -> Self {
        Self {
            slots: Default::default(),
            storage_requests: Default::default(),
            fallback: B256::ZERO,
            fail_storage: false,
        }
    }
}

impl MockL1Reader {
    pub fn insert(&self, address: Address, slot: U256, anchor: u64, value: U256) {
        self.set_u256(address, slot, anchor, value);
    }

    pub fn returning(value: B256) -> Self {
        Self {
            fallback: value,
            ..Default::default()
        }
    }

    pub fn failing_storage() -> Self {
        Self {
            fail_storage: true,
            ..Default::default()
        }
    }

    pub fn set_u256(&self, address: Address, slot: U256, block: u64, value: U256) {
        self.slots.lock().unwrap().insert(
            (address, B256::from(slot.to_be_bytes()), block),
            B256::from(value.to_be_bytes()),
        );
    }

    pub fn storage_requests(&self) -> Vec<L1Slot> {
        self.storage_requests.lock().unwrap().clone()
    }
}

impl L1StorageReader for MockL1Reader {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.storage_requests
            .lock()
            .unwrap()
            .push((account, slot, block_number));
        if self.fail_storage {
            return Err(L1StateError::StorageUnavailable {
                account,
                slot,
                block_number,
                reason: "RPC unavailable".into(),
            });
        }
        if let Some(value) = self
            .slots
            .lock()
            .unwrap()
            .get(&(account, slot, block_number))
            .copied()
        {
            return Ok(value);
        }

        Ok(self.fallback)
    }
}
