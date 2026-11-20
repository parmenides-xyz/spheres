use alloy_consensus::{BlockHeader as _, Header};
use alloy_primitives::{B256, U256, keccak256};
use sphere_primitives::constants::{MAX_UNPROCESSED_DEPOSITS, MAX_UNPROCESSED_TOKEN_ENABLEMENTS};

mod execution;
mod mpt;
mod types;

pub use execution::database::{ArcWitnessDatabase, WitnessDatabase, WitnessDatabaseError};
pub use mpt::StatelessSparseTrieError;
pub use types::*;

fn validate_arc_anchor(
    arc_block_number: u64,
    arc_block_hash: B256,
    public_inputs: &PublicInputs,
    ancestry_headers: &[alloy_primitives::Bytes],
) -> Result<(), Error> {
    if public_inputs.anchor_block_number < arc_block_number {
        return Err(Error::AnchorBlockNumberBeforeArc {
            arc_block_number,
            anchor_block_number: public_inputs.anchor_block_number,
        });
    }

    if public_inputs.anchor_block_number == arc_block_number {
        if !ancestry_headers.is_empty() {
            return Err(Error::UnexpectedArcAncestryHeaders);
        }
        if arc_block_hash != public_inputs.anchor_block_hash {
            return Err(Error::ArcAnchorHashMismatch {
                expected: public_inputs.anchor_block_hash,
                actual: arc_block_hash,
            });
        }
        return Ok(());
    }

    let expected_len = (public_inputs.anchor_block_number - arc_block_number) as usize;
    if ancestry_headers.len() != expected_len {
        return Err(Error::ArcAncestryLengthMismatch {
            expected: expected_len,
            actual: ancestry_headers.len(),
        });
    }

    let mut previous_number = arc_block_number;
    let mut previous_hash = arc_block_hash;
    for (index, encoded_header) in ancestry_headers.iter().enumerate() {
        let header: Header = alloy_rlp::decode_exact(encoded_header)
            .map_err(|_| Error::ArcAncestryHeaderDecoding { index })?;
        let expected_number = previous_number
            .checked_add(1)
            .ok_or(Error::ArcAncestryBlockNumberOverflow)?;
        if header.number() != expected_number {
            return Err(Error::ArcAncestryHeaderNumberMismatch {
                index,
                expected: expected_number,
                actual: header.number(),
            });
        }
        if header.parent_hash() != previous_hash {
            return Err(Error::ArcAncestryParentHashMismatch {
                index,
                expected: previous_hash,
                actual: header.parent_hash(),
            });
        }
        previous_number = header.number();
        previous_hash = keccak256(encoded_header);
    }

    if previous_hash != public_inputs.anchor_block_hash {
        return Err(Error::ArcAnchorHashMismatch {
            expected: public_inputs.anchor_block_hash,
            actual: previous_hash,
        });
    }
    Ok(())
}

fn validate_batch_block_shape(block: &SphereBlock, is_last: bool) -> Result<(), Error> {
    let valid = match (&block.arc_import, is_last) {
        (ArcImport::CheckpointOnly { .. }, false) => true,
        (ArcImport::Full { .. }, false) => block.finalize_withdrawal_batch_count.is_none(),
        (ArcImport::Full { .. }, true) => block.finalize_withdrawal_batch_count.is_some(),
        (ArcImport::CheckpointOnly { .. }, true) => false,
    };
    if !valid {
        return Err(Error::InvalidBatchShape);
    }
    Ok(())
}

fn validate_system_inputs(block: &SphereBlock, index: usize) -> Result<(), Error> {
    if block.arc_import.headers_rlp().is_empty() {
        return Err(Error::MissingArcHeaders { block_index: index });
    }
    match &block.arc_import {
        ArcImport::Full {
            deposits,
            enabled_tokens,
            ..
        } => {
            if deposits.len() > MAX_UNPROCESSED_DEPOSITS
                || enabled_tokens.len() > MAX_UNPROCESSED_TOKEN_ENABLEMENTS
            {
                return Err(Error::PortalWorkCapacityExceeded { block_index: index });
            }
        }
        ArcImport::CheckpointOnly { .. } => {
            if !block.transactions.is_empty()
                || block.finalize_withdrawal_batch_count.is_some()
                || !block.finalize_withdrawal_batch_encrypted_senders.is_empty()
            {
                return Err(Error::InvalidCheckpointOnlyBlock { block_index: index });
            }
        }
    }
    match block.finalize_withdrawal_batch_count {
        Some(count)
            if count != U256::from(block.finalize_withdrawal_batch_encrypted_senders.len()) =>
        {
            return Err(Error::FinalizationEncryptedSenderCountMismatch {
                block_index: index,
                expected: count,
                actual: block.finalize_withdrawal_batch_encrypted_senders.len(),
            });
        }
        None if !block.finalize_withdrawal_batch_encrypted_senders.is_empty() => {
            return Err(Error::FinalizationEncryptedSendersWithoutCount { block_index: index });
        }
        _ => {}
    }

    Ok(())
}

/// Errors emitted by the stateless state transition function.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The Sphere MPT witness did not prove one of its supplied reads.
    #[error(transparent)]
    MptValidation(#[from] StatelessSparseTrieError),
    /// A read against the provided state witness failed.
    #[error(transparent)]
    WitnessDatabase(#[from] WitnessDatabaseError),
    /// A checkpoint-only block carried operational inputs or transactions.
    #[error("checkpoint-only sphere block {block_index} contains operational inputs")]
    InvalidCheckpointOnlyBlock { block_index: usize },
    /// A block did not import any Arc headers.
    #[error("sphere block {block_index} contains no Arc headers")]
    MissingArcHeaders { block_index: usize },
    /// A full block exceeded a protocol-wide outstanding portal-work bound.
    #[error("sphere block {block_index} exceeds portal-work capacity")]
    PortalWorkCapacityExceeded { block_index: usize },
    /// A batch must end in a full operational block that finalizes withdrawals. Intermediate
    /// blocks may use either Arc import variant, but must not finalize withdrawals.
    #[error("invalid batch shape")]
    InvalidBatchShape,
    /// Finalization sender data was supplied without a finalization count.
    #[error("sphere block {block_index} has finalization senders without a count")]
    FinalizationEncryptedSendersWithoutCount { block_index: usize },
    /// Finalization sender data has a different length than its declared count.
    #[error(
        "sphere block {block_index} finalization sender count mismatch: expected {expected}, got {actual}"
    )]
    FinalizationEncryptedSenderCountMismatch {
        block_index: usize,
        expected: alloy_primitives::U256,
        actual: usize,
    },
    /// The requested anchor predates the proven Arc checkpoint.
    #[error("Arc anchor block {anchor_block_number} precedes checkpoint {arc_block_number}")]
    AnchorBlockNumberBeforeArc {
        arc_block_number: u64,
        anchor_block_number: u64,
    },
    /// Direct Arc anchoring must not include ancestry headers.
    #[error("direct Arc anchor included ancestry headers")]
    UnexpectedArcAncestryHeaders,
    /// The supplied ancestry chain has the wrong number of headers.
    #[error("Arc ancestry length mismatch: expected {expected}, got {actual}")]
    ArcAncestryLengthMismatch { expected: usize, actual: usize },
    /// An ancestry header is not complete Arc header RLP.
    #[error("invalid Arc ancestry header at index {index}")]
    ArcAncestryHeaderDecoding { index: usize },
    /// An ancestry header number is not consecutive.
    #[error("Arc ancestry header {index} number mismatch: expected {expected}, got {actual}")]
    ArcAncestryHeaderNumberMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    /// Arc block numbering overflowed while validating ancestry.
    #[error("Arc ancestry block number overflow")]
    ArcAncestryBlockNumberOverflow,
    /// An ancestry header does not point to the preceding Arc block.
    #[error(
        "Arc ancestry header {index} parent hash mismatch: expected {expected:?}, got {actual:?}"
    )]
    ArcAncestryParentHashMismatch {
        index: usize,
        expected: B256,
        actual: B256,
    },
    /// The direct Arc checkpoint or ancestry chain did not reach the anchor.
    #[error("Arc anchor hash mismatch: expected {expected:?}, got {actual:?}")]
    ArcAnchorHashMismatch { expected: B256, actual: B256 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
    use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
    use reth_trie_common::{
        EMPTY_ROOT_HASH, LeafNode, Nibbles, TrieAccount, TrieNode, root::state_root_unhashed,
    };
    use revm::Database as _;
    use revm::{
        DatabaseCommit as _,
        database::{State, states::bundle_state::BundleRetention},
    };
    use sphere_precompiles::L1StorageReader as _;

    fn empty_arc_witness(number: u64) -> ArcStateWitness {
        let header = Header {
            number,
            state_root: EMPTY_ROOT_HASH,
            ..Default::default()
        };

        ArcStateWitness {
            initial_arc_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: Vec::new(),
        }
    }

    fn witnessed_account_state(
        address: Address,
        nonce: u64,
        balance: U256,
        code_hash: B256,
        bytecodes: Vec<Bytes>,
        storage: Option<(U256, U256)>,
    ) -> (B256, SphereStateWitness) {
        let mut node_pool = Vec::new();
        let storage_root = match storage {
            Some((slot, value)) => {
                let storage_node = TrieNode::Leaf(LeafNode::new(
                    Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())),
                    alloy_rlp::encode(value),
                ));
                let encoded = alloy_rlp::encode(&storage_node);
                let root = keccak256(&encoded);
                node_pool.push(Bytes::from(encoded));
                root
            }
            None => EMPTY_ROOT_HASH,
        };
        let account = TrieAccount {
            nonce,
            balance,
            storage_root,
            code_hash,
        };
        let account_node = TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(keccak256(address)),
            alloy_rlp::encode(account),
        ));
        let encoded = alloy_rlp::encode(&account_node);
        let state_root = keccak256(&encoded);
        node_pool.push(Bytes::from(encoded));

        (
            state_root,
            SphereStateWitness {
                node_pool,
                bytecodes,
            },
        )
    }

    #[test]
    fn rejects_a_sphere_witness_without_the_parent_state_root_node() {
        let database = WitnessDatabase::from_sphere_state_witness(
            SphereStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            B256::repeat_byte(1),
        );

        assert!(matches!(
            database,
            Err(Error::MptValidation(
                StatelessSparseTrieError::MissingStateRootNode { state_root }
            )) if state_root == B256::repeat_byte(1)
        ));
    }

    #[test]
    fn resolves_sphere_state_reads_from_trie_leaves() {
        let account = Address::repeat_byte(0x11);
        let code = Bytes::from([0x60, 0x00]);
        let code_hash = keccak256(&code);
        let (state_root, witness) = witnessed_account_state(
            account,
            7,
            U256::from(42),
            code_hash,
            vec![code.clone()],
            Some((U256::from(3), U256::from(9))),
        );
        let mut database = WitnessDatabase::from_sphere_state_witness(witness, state_root).unwrap();

        let info = database.basic(account).unwrap().unwrap();
        assert_eq!(info.nonce, 7);
        assert_eq!(info.balance, U256::from(42));
        assert_eq!(
            database
                .code_by_hash(code_hash)
                .unwrap()
                .original_byte_slice(),
            code.as_ref()
        );
        assert_eq!(
            database.storage(account, U256::from(3)).unwrap(),
            U256::from(9)
        );
    }

    #[test]
    fn resolves_block_hash_from_eip2935_storage_witness() {
        let number = 42;
        let hash = B256::repeat_byte(0x42);
        let slot = U256::from(number % HISTORY_SERVE_WINDOW as u64);
        let (state_root, witness) = witnessed_account_state(
            HISTORY_STORAGE_ADDRESS,
            1,
            U256::ZERO,
            alloy_consensus::constants::KECCAK_EMPTY,
            Vec::new(),
            Some((slot, hash.into())),
        );
        let mut database = WitnessDatabase::from_sphere_state_witness(witness, state_root).unwrap();

        assert_eq!(database.block_hash(number).unwrap(), hash);
    }

    #[test]
    fn keeps_evm_state_in_the_bundle_overlay() {
        let address = Address::repeat_byte(0x22);
        let database = WitnessDatabase::from_sphere_state_witness(
            SphereStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            EMPTY_ROOT_HASH,
        )
        .unwrap();
        let mut state = State::builder()
            .with_database(database)
            .with_bundle_update()
            .build();
        assert_eq!(state.basic(address).unwrap(), None);
        let mut changes = revm::primitives::AddressMap::default();
        let mut account = revm::state::Account::default();
        account.info.balance = U256::from(42);
        account.mark_touch();
        changes.insert(address, account);

        state.commit(changes);
        state.merge_transitions(BundleRetention::PlainState);

        assert_eq!(
            state.basic(address).unwrap().unwrap().balance,
            U256::from(42)
        );
        assert_eq!(state.database.basic(address).unwrap(), None);
        assert!(state.bundle_state.state.contains_key(&address));

        let expected_account = TrieAccount {
            nonce: 0,
            balance: U256::from(42),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: alloy_consensus::constants::KECCAK_EMPTY,
        };
        let expected_root = state_root_unhashed([(address, expected_account)]);
        assert_eq!(
            state.database.state_root(state.bundle_state).unwrap(),
            expected_root
        );
    }

    #[test]
    fn ignores_stale_nodes_outside_the_bound_state_root() {
        let address = Address::repeat_byte(0x23);
        let stale_node = TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(keccak256(address)),
            alloy_rlp::encode(TrieAccount::default()),
        ));
        let mut database = WitnessDatabase::from_sphere_state_witness(
            SphereStateWitness {
                node_pool: vec![Bytes::from(alloy_rlp::encode(stale_node))],
                bytecodes: Vec::new(),
            },
            EMPTY_ROOT_HASH,
        )
        .unwrap();

        assert_eq!(database.basic(address).unwrap(), None);
    }

    #[test]
    fn rejects_sphere_bytecode_absent_from_the_bytecode_pool() {
        let account = Address::repeat_byte(0x44);
        let code_hash = keccak256([0x60, 0x00]);
        let (state_root, witness) =
            witnessed_account_state(account, 1, U256::from(2), code_hash, Vec::new(), None);
        let mut database = WitnessDatabase::from_sphere_state_witness(witness, state_root).unwrap();

        assert_eq!(
            database.code_by_hash(code_hash),
            Err(WitnessDatabaseError::MissingCode { code_hash })
        );
    }

    #[test]
    fn resolves_arc_state_from_its_initial_header() {
        let account = Address::repeat_byte(0x33);
        let slot = B256::repeat_byte(0x07);
        let database = ArcWitnessDatabase::from_arc_state_witness(empty_arc_witness(9)).unwrap();

        assert_eq!(
            database.read_l1_storage(account, slot, 9).unwrap(),
            B256::ZERO
        );
        assert!(database.read_l1_storage(account, slot, 8).is_err());
        assert_eq!(database.missing_read(), None);
    }

    #[test]
    fn reports_the_exact_missing_arc_storage_proof() {
        let account = Address::repeat_byte(0x33);
        let slot = B256::repeat_byte(0x07);
        let block_number = 9;
        let header = Header {
            number: block_number,
            state_root: B256::repeat_byte(0x44),
            ..Default::default()
        };
        let database = ArcWitnessDatabase::from_arc_state_witness(ArcStateWitness {
            initial_arc_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: Vec::new(),
        })
        .unwrap();

        assert!(
            database
                .read_l1_storage(account, slot, block_number)
                .is_err()
        );
        let missing = database.missing_read().unwrap();
        assert_eq!(missing.account, account);
        assert_eq!(missing.slot, slot);
        assert_eq!(missing.block_number, block_number);
    }

    #[test]
    fn fully_reveals_the_active_arc_checkpoint() {
        let account = Address::repeat_byte(0x34);
        let slot = U256::from(7);
        let value = U256::from(11);
        let (state_root, sphere_witness) = witnessed_account_state(
            account,
            0,
            U256::ZERO,
            alloy_consensus::constants::KECCAK_EMPTY,
            Vec::new(),
            Some((slot, value)),
        );
        let header = Header {
            number: 9,
            state_root,
            ..Default::default()
        };
        let database = ArcWitnessDatabase::from_arc_state_witness(ArcStateWitness {
            initial_arc_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: sphere_witness.node_pool,
        })
        .unwrap();

        assert_eq!(
            database.read_l1_storage(account, slot.into(), 9).unwrap(),
            B256::from(value)
        );
    }

    fn minimal_batch_witness() -> BatchWitness {
        let parent_header = Header {
            state_root: EMPTY_ROOT_HASH,
            gas_limit: 30_000_000,
            ..Default::default()
        };

        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: arc_execution_config::chain_ids::TESTNET_CHAIN_ID,
                sphere_id: 1,
                arc_block_number: 2,
                anchor_block_number: 2,
                anchor_block_hash: B256::ZERO,
                expected_withdrawal_batch_index: 3,
            },
            parent_header,
            sphere_blocks: Vec::new(),
            sphere_state_witness: SphereStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            arc_state_witness: empty_arc_witness(2),
            arc_ancestry_headers: Vec::new(),
        }
    }

    fn full_import(header_rlp: Bytes) -> ArcImport {
        ArcImport::Full {
            header_rlp,
            deposits: Vec::new(),
            decryptions: Vec::new(),
            enabled_tokens: Vec::new(),
        }
    }

    fn checkpoint_import(headers_rlp: Vec<Bytes>) -> ArcImport {
        ArcImport::CheckpointOnly { headers_rlp }
    }

    #[test]
    fn constructs_a_minimal_batch_witness() {
        let witness = minimal_batch_witness();

        assert_eq!(witness.public_inputs.sphere_id, 1);
        assert!(witness.sphere_blocks.is_empty());
    }

    #[test]
    fn batch_shape_rejects_intermediate_finalization() {
        let mut witness = minimal_batch_witness();
        for number in 1..=2 {
            witness.sphere_blocks.push(SphereBlock {
                number,
                parent_hash: B256::ZERO,
                timestamp: 100,

                beneficiary: Address::ZERO,
                arc_import: full_import(Bytes::from([0x01])),
                finalize_withdrawal_batch_count: Some(U256::ZERO),
                finalize_withdrawal_batch_encrypted_senders: Vec::new(),
                transactions: Vec::new(),
            });
        }
        validate_system_inputs(&witness.sphere_blocks[0], 0).unwrap();
        assert_eq!(
            validate_batch_block_shape(&witness.sphere_blocks[0], false),
            Err(Error::InvalidBatchShape)
        );
    }

    #[test]
    fn batch_shape_accepts_intermediate_full_block_without_finalization() {
        let block = SphereBlock {
            number: 1,
            parent_hash: B256::ZERO,
            timestamp: 100,

            beneficiary: Address::ZERO,
            arc_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        validate_system_inputs(&block, 0).unwrap();
        assert_eq!(validate_batch_block_shape(&block, false), Ok(()));
    }

    #[test]
    fn batch_shape_rejects_checkpoint_only_batch() {
        let mut witness = minimal_batch_witness();
        witness.sphere_blocks.push(SphereBlock {
            number: 1,
            parent_hash: B256::ZERO,
            timestamp: 100,

            beneficiary: Address::ZERO,
            arc_import: checkpoint_import(vec![Bytes::from([0x01]), Bytes::from([0x02])]),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        });
        validate_system_inputs(&witness.sphere_blocks[0], 0).unwrap();
        assert_eq!(
            validate_batch_block_shape(&witness.sphere_blocks[0], true),
            Err(Error::InvalidBatchShape)
        );
    }

    #[test]
    fn rejects_portal_work_above_capacity() {
        for (deposit_count, token_count) in [
            (MAX_UNPROCESSED_DEPOSITS + 1, 0),
            (0, MAX_UNPROCESSED_TOKEN_ENABLEMENTS + 1),
        ] {
            let block = SphereBlock {
                number: 1,
                parent_hash: B256::ZERO,
                timestamp: 0,

                beneficiary: Address::ZERO,
                arc_import: ArcImport::Full {
                    header_rlp: Bytes::from([0x01]),
                    deposits: vec![
                        sphere_contracts::QueuedDeposit {
                            depositType: sphere_contracts::DepositType::Deposit,
                            depositData: Bytes::new(),
                            rejected: false,
                        };
                        deposit_count
                    ],
                    decryptions: Vec::new(),
                    enabled_tokens: vec![
                        sphere_contracts::EnabledToken {
                            token: Address::ZERO,
                            name: String::new(),
                            symbol: String::new(),
                            currency: String::new(),
                        };
                        token_count
                    ],
                },
                finalize_withdrawal_batch_count: None,
                finalize_withdrawal_batch_encrypted_senders: Vec::new(),
                transactions: Vec::new(),
            };
            assert_eq!(
                validate_system_inputs(&block, 0),
                Err(Error::PortalWorkCapacityExceeded { block_index: 0 })
            );
        }
    }

    #[test]
    fn final_full_block_requires_withdrawal_finalization() {
        let witness = minimal_batch_witness();
        let mut block = SphereBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,

            beneficiary: Address::ZERO,
            arc_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        assert_eq!(validate_system_inputs(&block, 0), Ok(()));
        assert_eq!(
            validate_batch_block_shape(&block, true),
            Err(Error::InvalidBatchShape)
        );
        block.finalize_withdrawal_batch_count = Some(U256::ZERO);
        assert_eq!(validate_batch_block_shape(&block, true), Ok(()));
        block.arc_import = checkpoint_import(Vec::new());
        assert_eq!(
            validate_system_inputs(&block, 0),
            Err(Error::MissingArcHeaders { block_index: 0 })
        );
    }

    #[test]
    fn accepts_one_header_checkpoint_only_input() {
        let witness = minimal_batch_witness();
        let block = SphereBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,

            beneficiary: Address::ZERO,
            arc_import: checkpoint_import(vec![Bytes::from([0x01])]),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        assert_eq!(validate_system_inputs(&block, 0), Ok(()));
    }

    #[test]
    fn validates_an_arc_ancestry_anchor() {
        let checkpoint = Header {
            number: 7,
            ..Default::default()
        };
        let checkpoint_hash = checkpoint.hash_slow();
        let anchor = Header {
            parent_hash: checkpoint_hash,
            number: 8,
            ..Default::default()
        };
        let anchor_rlp = Bytes::from(alloy_rlp::encode(anchor));
        let anchor_hash = keccak256(&anchor_rlp);
        let mut public_inputs = minimal_batch_witness().public_inputs;
        public_inputs.arc_block_number = 7;
        public_inputs.anchor_block_number = 8;
        public_inputs.anchor_block_hash = anchor_hash;

        assert_eq!(
            validate_arc_anchor(
                7,
                checkpoint_hash,
                &public_inputs,
                std::slice::from_ref(&anchor_rlp)
            ),
            Ok(())
        );

        for len in 0..anchor_rlp.len() {
            assert_eq!(
                validate_arc_anchor(
                    7,
                    checkpoint_hash,
                    &public_inputs,
                    &[anchor_rlp.slice(..len)]
                ),
                Err(Error::ArcAncestryHeaderDecoding { index: 0 })
            );
        }
        let trailing = Bytes::from([anchor_rlp.as_ref(), &[0x80]].concat());
        assert_eq!(
            validate_arc_anchor(7, checkpoint_hash, &public_inputs, &[trailing]),
            Err(Error::ArcAncestryHeaderDecoding { index: 0 })
        );
    }
}
