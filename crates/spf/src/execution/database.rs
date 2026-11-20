//! REVM database adapters backed by stateless trie witnesses.

use std::sync::{Arc, Mutex};

use alloy_consensus::BlockHeader as _;
use alloy_consensus::Header;
use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use revm::{
    Database,
    database::states::bundle_state::BundleState,
    primitives::{AddressMap, B256Map, U256Map},
    state::{AccountInfo, Bytecode},
};
use sphere_precompiles::{L1StateError, L1StorageReader};

use crate::{
    ArcStateWitness, Error, SphereStateWitness, StatelessSparseTrieError, mpt::StatelessSparseTrie,
};

/// Errors emitted while resolving an execution read against a witness.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessDatabaseError {
    /// A state path could not be resolved from the Sphere or Arc node pool.
    #[error(transparent)]
    Mpt(#[from] StatelessSparseTrieError),
    /// REVM requested bytecode not supplied by the Sphere witness.
    #[error("missing bytecode in witness: {code_hash:?}")]
    MissingCode { code_hash: B256 },
    /// The Sphere witness supplied the same bytecode preimage more than once.
    #[error("duplicate bytecode hash in Sphere state witness: {code_hash:?}")]
    DuplicateBytecodeHash { code_hash: B256 },
    /// The execution inputs assigned two different hashes to one Sphere block number.
    #[error("conflicting block hash for {number}: expected {expected:?}, got {actual:?}")]
    ConflictingBlockHash {
        number: u64,
        expected: B256,
        actual: B256,
    },
    /// The initial Arc header is not a complete RLP-encoded Arc header.
    #[error("invalid initial Arc header in witness")]
    InvalidArcHeader,
}

impl revm::database_interface::DBErrorMarker for WitnessDatabaseError {}

/// REVM database backed by a root-bound, fully revealed Sphere state trie.
#[derive(Debug)]
pub struct WitnessDatabase {
    state: StatelessSparseTrie,
    accounts: AddressMap<Option<AccountInfo>>,
    storage: AddressMap<U256Map<U256>>,
    code_by_hash: B256Map<Bytecode>,
}

impl WitnessDatabase {
    /// Create a Sphere execution database rooted at the parent Sphere header's
    /// state root.
    ///
    /// The node pool is fully revealed and checked against `state_root` before
    /// this returns. Bytecode is looked up by the code hash proven in an
    /// account leaf.
    pub fn from_sphere_state_witness(
        witness: SphereStateWitness,
        state_root: B256,
    ) -> Result<Self, Error> {
        let SphereStateWitness {
            node_pool,
            bytecodes,
        } = witness;
        let state = StatelessSparseTrie::new(state_root, &node_pool)?;
        let mut code_by_hash = B256Map::default();
        for code in bytecodes {
            let bytecode = Bytecode::new_raw(code);
            let code_hash = bytecode.hash_slow();
            if code_by_hash.insert(code_hash, bytecode).is_some() {
                return Err(WitnessDatabaseError::DuplicateBytecodeHash { code_hash }.into());
            }
        }

        Ok(Self {
            state,
            accounts: AddressMap::default(),
            storage: AddressMap::default(),
            code_by_hash,
        })
    }

    /// Apply one block's execution changes to the current Sphere state trie and
    /// return the resulting post-state root.
    pub(crate) fn state_root(
        &mut self,
        bundle_state: BundleState,
    ) -> Result<B256, StatelessSparseTrieError> {
        // Advance the trie from the previous block's root using this block's changes.
        let state = reth_trie_common::HashedPostState::from_bundle_state::<
            reth_trie_common::KeccakKeyHasher,
        >(bundle_state.state());
        let state_root = self.state.calculate_state_root(state)?;

        // Keep database read caches coherent with the newly advanced trie.
        for (address, account) in bundle_state.state() {
            self.accounts.insert(*address, account.info.clone());

            if account.status.is_storage_known() {
                self.storage.remove(address);
            }

            let storage_entry = self.storage.entry(*address).or_default();
            for (slot, value) in account.storage.iter() {
                storage_entry.insert(*slot, value.present_value);
            }
        }

        Ok(state_root)
    }
}

impl Database for WitnessDatabase {
    type Error = WitnessDatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.accounts.get(&address) {
            return Ok(account.clone());
        }

        let account = self.state.account(address)?.map(|account| AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            account_id: None,
            code: None,
        });
        self.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash
            .get(&code_hash)
            .cloned()
            .ok_or(WitnessDatabaseError::MissingCode { code_hash })
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        if let Some(value) = self
            .storage
            .get(&address)
            .and_then(|slots| slots.get(&slot))
        {
            return Ok(*value);
        }

        let value = self.state.storage(address, slot)?;
        self.storage.entry(address).or_default().insert(slot, value);
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        // EIP-2935 makes historical block hashes part of the authenticated Sphere state.
        // Resolve BLOCKHASH through the history contract so the ordinary storage witness
        // proves the returned value against the parent header's state root.
        let slot = U256::from(number % HISTORY_SERVE_WINDOW as u64);
        Ok(self.storage(HISTORY_STORAGE_ADDRESS, slot)?.into())
    }
}

/// Arc state reader for the checkpoint header supplied in the witness.
///
/// When the shared node pool includes that checkpoint's root, it owns a fully
/// revealed immutable sparse trie. Otherwise it remains inactive and rejects
/// any Arc storage read as an incomplete witness.
#[derive(Clone, Debug)]
pub struct ArcWitnessDatabase {
    state: Option<Arc<StatelessSparseTrie>>,
    arc_block_hash: B256,
    arc_block_number: u64,
    node_pool: Arc<Vec<Bytes>>,
    missing_read: Arc<Mutex<Option<MissingArcStorageRead>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MissingArcStorageRead {
    pub(crate) account: Address,
    pub(crate) slot: B256,
    pub(crate) block_number: u64,
}

impl ArcWitnessDatabase {
    /// Construct the reader for the initial Arc checkpoint.
    pub fn from_arc_state_witness(witness: ArcStateWitness) -> Result<Self, Error> {
        let node_pool = Arc::new(witness.node_pool);
        let (state, arc_block_hash, arc_block_number) =
            checkpoint_state(&witness.initial_arc_header_rlp, node_pool.as_ref())?;

        Ok(Self {
            state,
            arc_block_hash,
            arc_block_number,
            node_pool,
            missing_read: Arc::default(),
        })
    }

    /// Return a reader rooted at an Arc header imported by the current Sphere
    /// block. `SphereInbox.advanceArc` validates that the header is the next
    /// checkpoint before any Arc-dependent system work executes.
    pub(crate) fn with_imported_checkpoint(
        self,
        header_rlp: &alloy_primitives::Bytes,
    ) -> Result<Self, Error> {
        let (state, arc_block_hash, arc_block_number) =
            checkpoint_state(header_rlp, self.node_pool.as_ref())?;

        Ok(Self {
            state,
            arc_block_hash,
            arc_block_number,
            node_pool: self.node_pool,
            missing_read: self.missing_read,
        })
    }

    /// Returns the checkpoint committed by the decoded initial Arc header.
    pub(crate) fn checkpoint(&self) -> (u64, B256) {
        (self.arc_block_number, self.arc_block_hash)
    }

    pub(crate) fn missing_read(&self) -> Option<MissingArcStorageRead> {
        *self
            .missing_read
            .lock()
            .expect("missing Arc storage read mutex poisoned")
    }

    fn record_missing_read(&self, account: Address, slot: B256, block_number: u64) {
        let mut missing = self
            .missing_read
            .lock()
            .expect("missing Arc storage read mutex poisoned");
        missing.get_or_insert(MissingArcStorageRead {
            account,
            slot,
            block_number,
        });
    }
}

fn checkpoint_state(
    header_rlp: &[u8],
    node_pool: &[Bytes],
) -> Result<(Option<Arc<StatelessSparseTrie>>, B256, u64), Error> {
    let header: Header =
        alloy_rlp::decode_exact(header_rlp).map_err(|_| WitnessDatabaseError::InvalidArcHeader)?;

    let state_root = header.state_root();
    let state = match StatelessSparseTrie::new(state_root, node_pool) {
        Ok(state) => Some(Arc::new(state)),
        Err(StatelessSparseTrieError::MissingStateRootNode { .. }) => None,
        Err(error) => return Err(error.into()),
    };

    Ok((state, keccak256(header_rlp), header.number()))
}

impl L1StorageReader for ArcWitnessDatabase {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        arc_block_number: u64,
    ) -> Result<B256, L1StateError> {
        if arc_block_number != self.arc_block_number {
            return Err(storage_unavailable(
                account,
                slot,
                arc_block_number,
                "witness has no root for the requested checkpoint",
            ));
        }

        let state = self.state.as_ref().ok_or_else(|| {
            self.record_missing_read(account, slot, arc_block_number);
            storage_unavailable(
                account,
                slot,
                arc_block_number,
                "witness does not include the checkpoint state root",
            )
        })?;
        let value = match state.storage(account, slot.into()) {
            Ok(value) => value,
            Err(
                error @ (StatelessSparseTrieError::IncompleteAccountProof { .. }
                | StatelessSparseTrieError::IncompleteStorageProof { .. }),
            ) => {
                self.record_missing_read(account, slot, arc_block_number);
                return Err(L1StateError::StorageUnavailable {
                    account,
                    slot,
                    block_number: arc_block_number,
                    reason: format!("incomplete Arc witness: {error}"),
                });
            }
            Err(error) => {
                return Err(L1StateError::StorageUnavailable {
                    account,
                    slot,
                    block_number: arc_block_number,
                    reason: format!("invalid Arc witness: {error}"),
                });
            }
        };
        Ok(value.into())
    }
}

fn storage_unavailable(
    account: Address,
    slot: B256,
    block_number: u64,
    reason: &'static str,
) -> L1StateError {
    L1StateError::StorageUnavailable {
        account,
        slot,
        block_number,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_trie_common::EMPTY_ROOT_HASH;

    #[test]
    fn checkpoint_requires_exact_header_rlp() {
        let mut header = Header::default();
        header.state_root = EMPTY_ROOT_HASH;
        header.number = 42;
        let encoded = alloy_rlp::encode(header);
        let (state, hash, number) = checkpoint_state(&encoded, &[]).unwrap();
        assert!(state.is_some());
        assert_eq!(hash, keccak256(&encoded));
        assert_eq!(number, 42);

        let mut invalid = (0..encoded.len())
            .map(|len| encoded[..len].to_vec())
            .collect::<Vec<_>>();
        invalid.push([encoded.as_slice(), &[0x80]].concat());
        for bytes in invalid {
            assert_eq!(
                checkpoint_state(&bytes, &[]).unwrap_err(),
                WitnessDatabaseError::InvalidArcHeader.into()
            );
        }
    }
}
