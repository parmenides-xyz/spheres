use crate::{ArcImport, SpherePayloadAttributes, SpherePayloadTypes, WithdrawalRevealEncryptor};
use alloy_consensus::{Header, Signed, TxLegacy};
use alloy_eips::eip4895::Withdrawals;
use alloy_evm::Evm;
use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolCall;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_errors::ProviderError;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_evm::{
    ConfigureEvm, Database, NextBlockEnvAttributes,
    execute::{BlockBuilder, BlockBuilderOutcome},
};
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_builder::{BuilderContext, components::PayloadBuilderBuilder};
use reth_payload_primitives::{PayloadAttributes, PayloadBuilderError};
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_primitives_traits::Recovered;
use reth_revm::cancelled::CancelOnDrop;
use reth_revm::{State, database::StateProviderDatabase};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use revm::context_interface::Block as _;
use sphere_chainspec::SphereChainSpec;
use sphere_contracts::spheres::{self as abi, SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS};
use sphere_l1::ArcStateExt;
use sphere_l1::PreparedL1Block;
use sphere_precompiles::L1StateError;
use sphere_primitives::envelope::{
    SPHERE_SYSTEM_TX_SENDER, SPHERE_SYSTEM_TX_SIGNATURE, SphereTxEnvelope,
};
use sphere_primitives::{SpherePrimitives, constants::MAX_RLP_BLOCK_SIZE};
use std::{error::Error, sync::Arc, time::Instant};
use tracing::{error, info, warn};

pub fn build_finalize_withdrawal_batch_tx(
    count: U256,
    block_number: u64,
    encrypted_senders: Vec<Bytes>,
    chain_id: u64,
) -> Recovered<SphereTxEnvelope> {
    let calldata = abi::ISphereOutbox::finalizeWithdrawalBatchCall {
        count,
        blockNumber: block_number,
        encryptedSenders: encrypted_senders,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: SPHERE_OUTBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE)),
        SPHERE_SYSTEM_TX_SENDER,
    )
}

pub fn build_advance_arc_tx(
    prepared: &PreparedL1Block,
    chain_id: u64,
) -> Recovered<SphereTxEnvelope> {
    build_advance_arc_tx_from_parts(
        prepared.header.header(),
        prepared.queued_deposits.clone(),
        prepared.decryptions.clone(),
        prepared.enabled_tokens.clone(),
        chain_id,
    )
}

/// Consume a throwaway prepared block without cloning its calldata vectors.
pub fn build_advance_arc_tx_owned(
    prepared: PreparedL1Block,
    chain_id: u64,
) -> Recovered<SphereTxEnvelope> {
    build_advance_arc_tx_from_parts(
        prepared.header.header(),
        prepared.queued_deposits,
        prepared.decryptions,
        prepared.enabled_tokens,
        chain_id,
    )
}

fn build_advance_arc_tx_from_parts(
    header: &Header,
    deposits: Vec<abi::QueuedDeposit>,
    decryptions: Vec<abi::DecryptionData>,
    enabled_tokens: Vec<abi::EnabledToken>,
    chain_id: u64,
) -> Recovered<SphereTxEnvelope> {
    let calldata = abi::ISphereInbox::advanceArcCall {
        header: alloy_rlp::encode(header).into(),
        deposits,
        decryptions,
        enabledTokens: enabled_tokens,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: SPHERE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE)),
        SPHERE_SYSTEM_TX_SENDER,
    )
}

/// Build a checkpoint-only `advanceArcHeaders(headers)` system transaction.
///
/// The executor requires this transaction to be the complete body of its Sphere block. Portal
/// deposits and token enablements remain pending until a later full `advanceArc` block.
pub fn build_advance_arc_headers_tx(
    headers: &[reth_primitives_traits::SealedHeader<Header>],
    chain_id: u64,
) -> Result<Recovered<SphereTxEnvelope>, PayloadBuilderError> {
    if headers.is_empty()
        || headers.len() > sphere_primitives::constants::MAX_ARC_HEADERS_PER_SPHERE_BLOCK
    {
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            "checkpoint-only Arc header range is empty or oversized",
        )));
    }
    let headers = headers
        .iter()
        .map(|header| alloy_rlp::encode(header.header()).into())
        .collect();
    let calldata = abi::ISphereInbox::advanceArcHeadersCall { headers }.abi_encode();
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: SPHERE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };
    Ok(Recovered::new_unchecked(
        SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE)),
        SPHERE_SYSTEM_TX_SENDER,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use reth_primitives_traits::SealedHeader;
    use sphere_contracts::spheres::ISphereInbox;
    #[test]
    fn withdrawal_batch_boundary_conditions() {
        let blocks = super::DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS;

        assert_eq!(blocks, 120);
        assert!(!super::should_finalize_withdrawal_batch(
            false, 119, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            false, 120, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            true, 121, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            false, 150, blocks, true, false
        ));
        // Deposit-only blocks must settle before the interval to reopen portal capacity.
        assert!(super::should_finalize_withdrawal_batch(
            false, 121, blocks, false, true
        ));
    }

    #[test]
    fn zero_batch_interval_finalizes_every_block() {
        assert_eq!(
            super::SpherePayloadFactory::new(0).withdrawal_batch_interval_blocks,
            1
        );
    }

    #[test]
    fn builds_checkpoint_only_import_with_all_headers() {
        let headers = [7, 8].map(|number| {
            SealedHeader::seal_slow(Header {
                number,
                ..Default::default()
            })
        });

        let recovered = super::build_advance_arc_headers_tx(&headers, 1337).unwrap();
        let SphereTxEnvelope::Legacy(signed) = recovered.inner() else {
            panic!("expected legacy transaction")
        };
        assert_eq!(signed.tx().chain_id, Some(1337));

        let call = ISphereInbox::advanceArcHeadersCall::abi_decode(&signed.tx().input).unwrap();
        assert_eq!(call.headers.len(), 2);
        for (encoded, expected) in call.headers.iter().zip(headers) {
            let decoded: Header = alloy_rlp::decode_exact(encoded).unwrap();
            assert_eq!(decoded.number, expected.number);
        }
    }
    #[test]
    fn test_build_advance_arc_tx_with_deposit() {
        let token = alloy_primitives::address!("0x0000000000000000000000000000000000001000");
        let sender = alloy_primitives::address!("0x0000000000000000000000000000000000001234");
        let header = Header {
            number: 1,
            ..Default::default()
        };

        // Build a PreparedL1Block directly — this test validates
        // `build_advance_arc_tx` calldata encoding, not `prepare`.
        let prepared = PreparedL1Block {
            header: SealedHeader::seal_slow(header),
            queued_deposits: vec![
                abi::QueuedDeposit {
                    depositType: abi::DepositType::WithdrawalBounceBack,
                    rejected: false,
                    depositData: alloy_primitives::Bytes::from(
                        alloy_sol_types::SolValue::abi_encode(&abi::WithdrawalBounceBackDeposit {
                            token,
                            to: Address::with_last_byte(1),
                            amount: 500_000,
                        }),
                    ),
                },
                abi::QueuedDeposit {
                    depositType: abi::DepositType::Deposit,
                    rejected: false,
                    depositData: alloy_primitives::Bytes::from(
                        alloy_sol_types::SolValue::abi_encode(&abi::Deposit {
                            token,
                            sender,
                            amount: 300_000,
                            arcRefundRecipient: sender,
                            keyIndex: U256::ZERO,
                            encrypted: abi::DepositPayload {
                                ephemeralPubkeyX: B256::with_last_byte(0xDD),
                                ephemeralPubkeyYParity: 0x02,
                                ciphertext: vec![0xAA; 64].into(),
                                nonce: [0x05; 12].into(),
                                tag: [0x06; 16].into(),
                            },
                        }),
                    ),
                },
            ],
            decryptions: vec![abi::DecryptionData {
                sharedSecret: B256::ZERO,
                sharedSecretYParity: 0x02,
                cpProof: abi::ChaumPedersenProof {
                    s: B256::ZERO,
                    c: B256::ZERO,
                },
            }],
            enabled_tokens: vec![],
            follows_checkpoint_blocks: false,
        };

        let recovered_tx = super::build_advance_arc_tx(&prepared, 1337);

        // Decode the calldata to verify structure.
        let envelope = recovered_tx.inner();
        let input = match envelope {
            SphereTxEnvelope::Legacy(signed) => {
                assert_eq!(signed.tx().chain_id, Some(1337));
                &signed.tx().input
            }
            _ => panic!("expected Legacy tx"),
        };
        let decoded = ISphereInbox::advanceArcCall::abi_decode(input)
            .expect("calldata should decode as advanceArc");

        // Should have 2 queued deposits
        assert_eq!(decoded.deposits.len(), 2, "should have 2 queued deposits");

        // The internal withdrawal bounce-back keeps its dedicated discriminator.
        assert_eq!(
            decoded.deposits[0].depositType,
            abi::DepositType::WithdrawalBounceBack,
            "first entry should be a withdrawal bounce-back"
        );

        // Second should be Encrypted
        assert_eq!(
            decoded.deposits[1].depositType,
            abi::DepositType::Deposit,
            "second deposit should be Encrypted"
        );

        // Should have exactly 1 DecryptionData (one per encrypted deposit)
        assert_eq!(
            decoded.decryptions.len(),
            1,
            "should have 1 DecryptionData for the encrypted deposit"
        );
    }
}

/// Default empty-batch cadence: every 120 sphere blocks (~60 sec at Arc's 500 ms block time).
pub const DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS: u64 = 120;

/// Safety margin reserved out of [`MAX_RLP_BLOCK_SIZE`] for everything in the block other than
/// pool transactions: the header, RLP list framing, `advanceArc`, `finalizeWithdrawalBatch`
/// and the outer RLP string header.
///
/// Note: `finalizeWithdrawalBatch` is not bounded(~200 bytes per withdrawal).
/// So a large enough backlog can exceed this margin. OK because the cap is a soft target: block
/// size is not consensus-validated, so an overshoot creates a
/// warning, not a failed build. The p2p transport message cap `MAX_MESSAGE_SIZE` must stay comfortably above
/// [`MAX_RLP_BLOCK_SIZE`] so such blocks still replicate.
const BLOCK_SIZE_SAFETY_MARGIN: usize = 1024 * 1024;

/// Diagnostic retained when upstream Arc precompile storage stringifies an [`L1StateError`].
const L1_STORAGE_UNAVAILABLE_ERROR_PREFIX: &str = "Arc L1 storage unavailable";

/// Factory for constructing the sphere payload builder.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpherePayloadFactory {
    withdrawal_batch_interval_blocks: u64,
    withdrawal_reveal_encryptor: Option<Arc<dyn WithdrawalRevealEncryptor>>,
}

impl Default for SpherePayloadFactory {
    fn default() -> Self {
        Self::new(DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS)
    }
}

impl SpherePayloadFactory {
    /// Create a factory that finalizes empty withdrawal batches every `interval_blocks` sphere blocks.
    pub fn new(withdrawal_batch_interval_blocks: u64) -> Self {
        Self {
            withdrawal_batch_interval_blocks: withdrawal_batch_interval_blocks.max(1),
            withdrawal_reveal_encryptor: None,
        }
    }

    pub fn with_withdrawal_reveal_encryptor(
        mut self,
        encryptor: Arc<dyn WithdrawalRevealEncryptor>,
    ) -> Self {
        self.withdrawal_reveal_encryptor = Some(encryptor);
        self
    }
}
impl<Node, Pool, EvmConfig> PayloadBuilderBuilder<Node, Pool, EvmConfig> for SpherePayloadFactory
where
    Node: FullNodeTypes,
    Node::Types: NodeTypes<
            Primitives = SpherePrimitives,
            ChainSpec = SphereChainSpec,
            Payload = SpherePayloadTypes,
        >,
    EvmConfig: ConfigureEvm<Primitives = SpherePrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = SphereTxEnvelope>>
        + Unpin
        + 'static,
{
    type PayloadBuilder = SpherePayloadBuilder<Node::Provider, Pool, EvmConfig>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: EvmConfig,
    ) -> eyre::Result<Self::PayloadBuilder> {
        Ok(SpherePayloadBuilder {
            pool,
            provider: ctx.provider().clone(),
            evm_config,
            withdrawal_batch_interval_blocks: self.withdrawal_batch_interval_blocks,
            withdrawal_reveal_encryptor: self.withdrawal_reveal_encryptor.clone(),
        })
    }
}

/// Sphere payload builder that executes `advanceArc` system txs + pool txs.
#[derive(Debug, Clone)]
pub struct SpherePayloadBuilder<Provider, Pool, EvmConfig> {
    /// Transaction pool for selecting pool txs to include in the block.
    pool: Pool,
    /// State provider for reading chain state during block building.
    provider: Provider,
    /// Sphere-specific EVM configuration (precompiles, hardfork spec, gas params).
    evm_config: EvmConfig,
    /// Runs disposable simulations on Reth's dedicated prewarming pool.

    /// Number of sphere blocks between withdrawal batch boundaries.
    withdrawal_batch_interval_blocks: u64,
    /// Encrypts authenticated-withdrawal sender reveal data for batch finalization.
    withdrawal_reveal_encryptor: Option<Arc<dyn WithdrawalRevealEncryptor>>,
}
impl<Provider, Pool, EvmConfig> PayloadBuilder for SpherePayloadBuilder<Provider, Pool, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = SpherePrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
    Provider:
        StateProviderFactory + ChainSpecProvider<ChainSpec = SphereChainSpec> + Clone + 'static,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = SphereTxEnvelope>>
        + Unpin
        + 'static,
{
    type Attributes = SpherePayloadAttributes;
    type BuiltPayload = EthBuiltPayload<SpherePrimitives>;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let BuildArguments {
            mut cached_reads,
            config,
            cancel,
            ..
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id: _,
        } = config;

        let start = Instant::now();

        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let arc_import = attributes.arc_import();
        let imported_headers = match arc_import {
            ArcImport::Full(prepared) => core::slice::from_ref(&prepared.header),
            ArcImport::CheckpointOnly(headers) => headers.as_slice(),
        };
        validate_l1_continuity(state_provider.as_ref(), imported_headers)?;
        let final_imported = imported_headers.last().expect("validated nonempty import");
        let checkpoint_only = arc_import.is_checkpoint_only();
        let follows_checkpoint_blocks = arc_import.follows_checkpoint_blocks();
        let total_deposits = arc_import.total_deposits();
        let enabled_tokens = arc_import.enabled_tokens();

        if arc_import.is_checkpoint_only() {
            info!(
                target: "sphere::payload",
                sphere_block = parent_header.number() + 1,
                l1_block = final_imported.number,
                header_count = imported_headers.len(),
                "Including advanceHeaders system tx (chain continuity OK)"
            );
        } else {
            info!(
                target: "sphere::payload",
                sphere_block = parent_header.number() + 1,
                l1_block = final_imported.number,
                deposits = total_deposits,
                enabled_tokens,
                "Including advanceArc system tx (chain continuity OK)"
            );
        }

        let state = StateProviderDatabase::new(state_provider.as_ref());
        let mut db = State::builder()
            .with_database(
                Box::new(cached_reads.as_db_mut(state)) as Box<dyn Database<Error = ProviderError>>
            )
            .with_bundle_update()
            .build();

        let chain_spec = self.provider.chain_spec();
        let chain_id = chain_spec.chain_id();

        let block_gas_limit = parent_header.gas_limit();

        let next_block_env_attributes = NextBlockEnvAttributes {
            timestamp: attributes.timestamp(),
            suggested_fee_recipient: attributes.suggested_fee_recipient(),
            prev_randao: attributes.prev_randao(),
            gas_limit: block_gas_limit,
            parent_beacon_block_root: attributes.parent_beacon_block_root(),
            withdrawals: attributes.withdrawals().cloned().map(Withdrawals::new),
            extra_data: attributes.extra_data(),
            slot_number: attributes.slot_number(),
        };
        let mut builder = self
            .evm_config
            .builder_for_next_block(&mut db, &parent_header, next_block_env_attributes.clone())
            .map_err(PayloadBuilderError::other)?;
        let base_fee = builder.evm().block().basefee();
        let block_number: u64 = builder
            .evm()
            .block()
            .number()
            .try_into()
            .expect("block number fits u64");

        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        // Execute advanceArc system transaction — exactly one per sphere block.
        let opening_tx = match arc_import {
            ArcImport::Full(prepared) => build_advance_arc_tx(prepared, chain_id),
            ArcImport::CheckpointOnly(headers) => build_advance_arc_headers_tx(headers, chain_id)?,
        };
        builder
            .execute_transaction(opening_tx)
            .map(|_| ())
            .map_err(PayloadBuilderError::evm)
            .map_err(|err| {
                error!(
                    ?err,
                    l1_block = final_imported.number,
                    deposits = total_deposits,
                    "advanceArc system tx failed"
                );
                err
            })?;
        if !checkpoint_only {
            // Execute pool transactions until either all of them fit or their packed RLP bytes reach
            // the size budget
            // The block executor owns gas-capacity accounting.
            let pool_tx_size_budget = MAX_RLP_BLOCK_SIZE - BLOCK_SIZE_SAFETY_MARGIN;
            let mut best_txs = self
                .pool
                .best_transactions_with_attributes(BestTransactionsAttributes::new(base_fee, None));
            best_txs.set_skip_blobs(true);
            if execute_pool_transactions(
                |tx| builder.execute_transaction(tx).map(|_| ()),
                &mut best_txs,
                &cancel,
                pool_tx_size_budget,
            )? == PoolExecutionOutcome::Cancelled
            {
                return Ok(BuildOutcome::Cancelled);
            }

            finalize_withdrawal_batch_if_needed(
                &mut builder,
                block_number,
                self.withdrawal_batch_interval_blocks,
                follows_checkpoint_blocks,
                total_deposits > 0,
                self.withdrawal_reveal_encryptor.as_deref(),
                chain_id,
            )?;
        }

        let BlockBuilderOutcome {
            execution_result,
            hashed_state: _,
            trie_updates: _,
            block,
        } = builder.finish(&*state_provider, None)?;

        let requests = chain_spec
            .is_prague_active_at_timestamp(attributes.timestamp())
            .then_some(execution_result.requests.clone());

        let sealed_block = Arc::new(block.sealed_block().clone());
        let execution_block_size_estimate = sealed_block.rlp_length();
        if execution_block_size_estimate > MAX_RLP_BLOCK_SIZE {
            warn!(
                block_size_bytes = execution_block_size_estimate,
                max_rlp_block_size = MAX_RLP_BLOCK_SIZE,
                "built block exceeds the soft RLP size cap"
            );
        }

        let elapsed = start.elapsed();
        info!(
            number = sealed_block.number(),
            l1_block = final_imported.number(),
            l1_hash = ?final_imported.hash(),
            hash = ?sealed_block.hash(),
            gas_used = sealed_block.gas_used(),
            deposits = total_deposits,
            tx_count = sealed_block.transaction_count(),
            block_size_bytes = execution_block_size_estimate,
            ?elapsed,
            "Built sphere payload"
        );

        let payload = EthBuiltPayload::new(sealed_block, U256::ZERO, requests, None);
        // the payload to prevent reth from re-triggering try_build on the rebuild interval.
        // Without this, the next rebuild attempt would find the deposit queue empty.
        Ok(BuildOutcome::Freeze(payload))
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        MissingPayloadBehaviour::AwaitInProgress
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, Header>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        self.try_build(BuildArguments::new(
            Default::default(),
            None,
            None,
            config,
            Default::default(),
            Default::default(),
        ))?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Validate that the prepared L1 block is the next block expected by ArcState.
fn validate_l1_continuity(
    state_provider: &dyn StateProvider,
    headers: &[reth_primitives_traits::SealedHeader<Header>],
) -> Result<(), PayloadBuilderError> {
    let stored_l1 = state_provider
        .arc_num_hash()
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
    let expected_block_number = stored_l1.number + 1;

    info!(
        target: "sphere::payload",
        stored_l1_block_hash = %stored_l1.hash,
        expected_arc_block_number = expected_block_number,
        "ArcState current state"
    );

    if headers.is_empty() {
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            "Arc import contains no headers",
        )));
    }
    let mut expected_number = expected_block_number;
    let mut expected_hash = stored_l1.hash;
    for header in headers {
        if header.number != expected_number {
            error!(
                target: "sphere::payload",
                got = header.number,
                expected = expected_number,
                "L1 block number mismatch — chain continuity broken"
            );
            return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
                format!(
                    "L1 block number mismatch: got {} expected {expected_block_number}",
                    header.number
                ),
            )));
        }

        if header.parent_hash != expected_hash {
            error!(
                target: "sphere::payload",
                got = %header.parent_hash,
                expected = %expected_hash,
                l1_block = header.number,
                "L1 parent hash mismatch — chain continuity broken"
            );
            return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
                format!(
                    "L1 parent hash mismatch at block {}: got {} expected {}",
                    header.number, header.parent_hash, expected_hash
                ),
            )));
        }
        expected_number = expected_number.checked_add(1).ok_or_else(|| {
            PayloadBuilderError::Internal(reth_errors::RethError::msg("Arc block number overflow"))
        })?;
        expected_hash = header.hash();
    }

    Ok(())
}

/// Execute the best pool transactions until the iterator is exhausted or the build is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolExecutionOutcome {
    Complete,
    Cancelled,
}

/// Execute the best pool transactions, skipping any whose RLP size would push the packed pool
/// transaction bytes past `pool_tx_size_budget`.
fn execute_pool_transactions<T, F, P>(
    mut execute_tx: F,
    best_txs: &mut T,
    cancel: &CancelOnDrop,
    pool_tx_size_budget: usize,
) -> Result<PoolExecutionOutcome, PayloadBuilderError>
where
    P: PoolTransaction<Consensus = SphereTxEnvelope>,
    T: BestTransactions<Item = Arc<ValidPoolTransaction<P>>>,
    F: FnMut(Recovered<SphereTxEnvelope>) -> Result<(), reth_evm::block::BlockExecutionError>,
{
    let mut packed_tx_bytes = 0usize;
    while let Some(pool_tx) = best_txs.next() {
        if cancel.is_cancelled() {
            return Ok(PoolExecutionOutcome::Cancelled);
        }

        let packed_bytes_with_tx =
            packed_tx_bytes.saturating_add(pool_tx.transaction.encoded_length());
        if packed_bytes_with_tx > pool_tx_size_budget {
            best_txs.mark_invalid(
                &pool_tx,
                &InvalidPoolTransactionError::OversizedData {
                    size: packed_bytes_with_tx,
                    limit: pool_tx_size_budget,
                },
            );
            continue;
        }

        let tx = pool_tx.transaction.clone_into_consensus();
        match execute_tx(tx) {
            Ok(_) => packed_tx_bytes = packed_bytes_with_tx,
            Err(reth_evm::block::BlockExecutionError::Validation(
                reth_evm::block::BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit,
                    block_available_gas,
                },
            )) => {
                best_txs.mark_invalid(
                    &pool_tx,
                    &InvalidPoolTransactionError::ExceedsGasLimit(
                        transaction_gas_limit,
                        block_available_gas,
                    ),
                );
            }
            Err(reth_evm::block::BlockExecutionError::Validation(
                reth_evm::block::BlockValidationError::InvalidTx { error, .. },
            )) => {
                if !error.is_nonce_too_low() {
                    best_txs.mark_invalid(
                        &pool_tx,
                        &InvalidPoolTransactionError::Consensus(
                            reth_primitives_traits::transaction::error::InvalidTransactionError::TxTypeNotSupported,
                        ),
                    );
                }
            }
            Err(reth_evm::block::BlockExecutionError::Internal(
                reth_evm::block::InternalBlockExecutionError::EVM { ref error, .. },
            )) if is_l1_storage_unavailable(error.as_ref()) => {
                warn!(
                    target: "sphere::payload",
                    %error,
                    tx_hash = %pool_tx.hash(),
                    "skipping pool tx due to transient RPC error"
                );
            }
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        }
    }

    Ok(PoolExecutionOutcome::Complete)
}

fn is_l1_storage_unavailable(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<L1StateError>()
            .is_some_and(L1StateError::is_storage_unavailable)
            || error
                .to_string()
                .contains(L1_STORAGE_UNAVAILABLE_ERROR_PREFIX)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Finalize a batch after processing deposits, with pending withdrawals, or at a batch boundary.
fn finalize_withdrawal_batch_if_needed<B>(
    builder: &mut B,
    block_number: u64,
    interval_blocks: u64,
    follows_checkpoint_blocks: bool,
    has_processed_deposits: bool,
    encryptor: Option<&dyn WithdrawalRevealEncryptor>,
    chain_id: u64,
) -> Result<(), PayloadBuilderError>
where
    B: BlockBuilder<Primitives = SpherePrimitives>,
{
    let pending_withdrawals =
        read_pending_withdrawals_from_outbox(builder.evm_mut(), block_number)?;
    if !should_finalize_withdrawal_batch(
        !pending_withdrawals.is_empty(),
        block_number,
        interval_blocks,
        follows_checkpoint_blocks,
        has_processed_deposits,
    ) {
        return Ok(());
    }

    let encrypted_senders = pending_withdrawals
        .iter()
        .map(|request| {
            if request.revealTo.is_empty() {
                Ok(Bytes::new())
            } else {
                let encryptor = encryptor.ok_or_else(|| {
                    PayloadBuilderError::Internal(reth_errors::RethError::msg(
                        "withdrawal reveal encryption requested but no encryptor is configured",
                    ))
                })?;
                encryptor
                    .encrypt_sender(
                        request.revealTo.as_ref(),
                        request.sender,
                        request.txHash,
                        request.fallbackNonce,
                    )
                    .map(Bytes::from)
                    .ok_or_else(|| {
                        PayloadBuilderError::Internal(reth_errors::RethError::msg(format!(
                            "failed to encrypt authenticated sender reveal for tx {}",
                            request.txHash
                        )))
                    })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = U256::from(pending_withdrawals.len());
    let finalize_tx =
        build_finalize_withdrawal_batch_tx(count, block_number, encrypted_senders, chain_id);
    builder
        .execute_transaction(finalize_tx)
        .map(|_| ())
        .map_err(PayloadBuilderError::evm)
        .map_err(|err| {
            error!(
                ?err,
                block_number, "finalizeWithdrawalBatch system tx failed"
            );
            err
        })
}

fn should_finalize_withdrawal_batch(
    has_pending_withdrawals: bool,
    block_number: u64,
    interval_blocks: u64,
    follows_checkpoint_blocks: bool,
    has_processed_deposits: bool,
) -> bool {
    has_pending_withdrawals
        || has_processed_deposits
        || block_number.is_multiple_of(interval_blocks)
        || follows_checkpoint_blocks
}

/// Read all pending withdrawals in the SphereOutbox
fn read_pending_withdrawals_from_outbox<E>(
    evm: &mut E,
    block_number: u64,
) -> Result<Vec<abi::ISphereOutbox::PendingWithdrawal>, PayloadBuilderError>
where
    E: Evm,
{
    let calldata = abi::ISphereOutbox::getPendingWithdrawalsCall {}.abi_encode();
    let call_result = evm
        .transact_system_call(
            SPHERE_SYSTEM_TX_SENDER,
            SPHERE_OUTBOX_ADDRESS,
            calldata.into(),
        )
        .map_err(|err| {
            error!(
                ?err,
                block_number, "SphereOutbox getPendingWithdrawals view call failed"
            );
            PayloadBuilderError::evm(err)
        })?;

    if !call_result.result.is_success() {
        error!(
            target: "sphere::payload",
            block_number,
            result = ?call_result.result,
            "SphereOutbox getPendingWithdrawals view call failed"
        );
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            format!(
                "SphereOutbox getPendingWithdrawals view failed at sphere block {block_number}"
            ),
        )));
    }
    let output = call_result.result.into_output().unwrap_or_default();

    abi::ISphereOutbox::getPendingWithdrawalsCall::abi_decode_returns(&output).map_err(|err| {
        PayloadBuilderError::Internal(reth_errors::RethError::msg(format!(
            "failed to decode getPendingWithdrawals return data: {err}"
        )))
    })
}
