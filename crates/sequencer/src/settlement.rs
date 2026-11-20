use crate::Block;
use crate::SphereSequencerProvider;
use alloy_consensus::{Transaction, TxReceipt as _, transaction::TxHashRef as _};
use alloy_eips::BlockHashOrNumber;
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::SolCall;
use reth_ethereum_primitives::Receipt;
use reth_storage_api::BlockNumReader;
use sphere_contracts::{self as abi, ArcAdvanced, ISphereOutbox, LegacyArcAdvanced};
use std::collections::BTreeMap;
pub(crate) static L1_SUBMISSION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
use crate::attestation::{
    AttestationDomain, SettlementAttestation, SettlementCertificate, SignedSettlementAttestation,
};
use alloy_eips::eip2935::HISTORY_SERVE_WINDOW;
use alloy_network::{Ethereum, ReceiptResponse};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_provider::{DynProvider, Provider};
use alloy_rlp::Encodable;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolEvent, SolValue};
use eyre::{OptionExt as _, Result, WrapErr as _, ensure};
use futures::{StreamExt, TryStreamExt};
use parking_lot::RwLock;
use schnellru::{ByLength, LruMap};
use sphere_contracts::{
    BatchSubmitted, BlockTransition, DepositQueueTransition, LegacyBatchSubmitted, SpherePortal,
    TokenEnablementTransition,
};
use sphere_prover::{ProofBundle, VerifierMode};
use std::{fmt, sync::OnceLock, time::Duration};
use tokio::time::{Instant, sleep};
use tracing::{info, instrument, warn};
#[derive(Debug)]
pub enum BatchSubmitError {
    PortalAdvanced,
    PreparedAnchorInvalid(eyre::Report),
    Other(eyre::Report),
}

impl From<eyre::Report> for BatchSubmitError {
    fn from(error: eyre::Report) -> Self {
        Self::Other(error)
    }
}

impl fmt::Display for BatchSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortalAdvanced => {
                formatter.write_str("portal already committed the batch height")
            }
            Self::PreparedAnchorInvalid(error) => error.fmt(formatter),
            Self::Other(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BatchSubmitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PreparedAnchorInvalid(error) | Self::Other(error) => Some(error.as_ref()),
            Self::PortalAdvanced => None,
        }
    }
}

/// Safety margin (~3 min at 500ms block time) to avoid race conditions where
/// the block falls out of the window between our check and on-chain execution.
const DEFAULT_EIP2935_SAFETY_MARGIN: u64 = 360;

/// Maximum number of encoded L1 headers retained between ancestry submissions.
///
/// At roughly 600 bytes per header, this caps payload storage near 150 MiB plus
/// map overhead while covering more than the current Sphere E recovery gap.
const DEFAULT_ANCESTRY_HEADER_CACHE_CAPACITY: u32 = 262_144;

/// Bounded gas for one `submitBatch` call when gas estimation is unavailable.
///
/// Estimation against state N cannot see hash(N) in EIP-2935, but a transaction submitted after
/// observing N can only execute in N+1 or later, where that hash is available. Eight certificate
/// signatures still fit comfortably within this limit.
const SUBMIT_BATCH_GAS_LIMIT: u64 = 2_000_000;
/// EIP-2935 anchor limits used by the batch submitter.
///
/// Production uses the real 8191-block EIP-2935 history window with a safety
/// margin. This type exists primarily so tests can shrink that otherwise large
/// window and exercise ancestry behavior without mining thousands of L1 blocks.
/// Production code should normally use [`Default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchAnchorConfig {
    /// Total L1 block-hash history window to treat as available for EIP-2935
    /// anchoring.
    history_window: u64,
    /// Number of most-recent L1 blocks to avoid when choosing an anchor, reducing
    /// the chance that an anchor ages out before the on-chain transaction lands.
    safety_margin: u64,
}

impl BatchAnchorConfig {
    /// Build an anchor config with explicit limits.
    pub fn new(history_window: u64, safety_margin: u64) -> Result<Self> {
        if history_window == 0 {
            return Err(eyre::eyre!("EIP-2935 history window must be non-zero"));
        }

        if safety_margin >= history_window {
            return Err(eyre::eyre!(
                "EIP-2935 safety margin ({safety_margin}) must be smaller than history window ({history_window})"
            ));
        }

        Ok(Self {
            history_window,
            safety_margin,
        })
    }

    /// Configured history window in L1 blocks.
    pub const fn history_window(self) -> u64 {
        self.history_window
    }

    /// Configured safety margin in L1 blocks.
    pub const fn safety_margin(self) -> u64 {
        self.safety_margin
    }

    /// Effective direct-submission window after subtracting the safety margin.
    pub const fn effective_window(self) -> u64 {
        self.history_window - self.safety_margin
    }
}

impl Default for BatchAnchorConfig {
    fn default() -> Self {
        Self {
            history_window: HISTORY_SERVE_WINDOW as u64,
            safety_margin: DEFAULT_EIP2935_SAFETY_MARGIN,
        }
    }
}

/// Submits sphere batches to the SpherePortal contract on Arc L1.
///
/// Holds a contract instance pointing at the portal, backed by a shared
/// [`DynProvider`] with the sequencer's signing wallet.
pub struct BatchSubmitter {
    /// SpherePortal contract address on Arc L1 (used in tracing spans).
    portal_address: Address,
    /// Shared L1 provider (HTTP or WS) for querying the current block number
    /// (EIP-2935 window check). The same provider backs the `portal` contract
    /// instance.
    l1_provider: DynProvider<Ethereum>,
    /// SpherePortal contract instance for calling `submitBatch` and reading
    /// on-chain state such as `blockHash()`.
    portal: SpherePortal::SpherePortalInstance<DynProvider<Ethereum>, Ethereum>,
    /// Immutable portal and chain identifiers, populated by the first metadata multicall.
    stable_portal_metadata: OnceLock<StablePortalMetadata>,
    /// Local sequencer key used to produce a 1-of-1 settlement certificate.
    signer: Option<PrivateKeySigner>,
    /// Concurrency for pipelined L1 header fetching in ancestry mode.
    l1_fetch_concurrency: usize,
    /// EIP-2935 history and safety-margin limits used for anchor decisions.
    anchor_config: BatchAnchorConfig,
    /// Validated, RLP-encoded L1 headers retained across overlapping ancestry
    /// requests. Settlement batches are submitted in order, so later requests
    /// can reuse almost the entire preceding range.
    ancestry_header_cache: RwLock<LruMap<u64, CachedAncestryHeader>>,
}
impl BatchSubmitter {
    /// Shared Arc L1 provider backing portal reads and submissions.
    pub(crate) const fn l1_provider(&self) -> &DynProvider<Ethereum> {
        &self.l1_provider
    }

    /// Create a batch submitter without a certificate signer.
    ///
    /// This is useful for read-only operations and tests. Batch submission returns an error.
    pub fn new(portal_address: Address, l1_provider: DynProvider<Ethereum>) -> Self {
        Self::with_anchor_config(portal_address, l1_provider, BatchAnchorConfig::default())
    }

    /// Create a new batch submitter with custom EIP-2935 anchor limits.
    pub fn with_anchor_config(
        portal_address: Address,
        l1_provider: DynProvider<Ethereum>,
        anchor_config: BatchAnchorConfig,
    ) -> Self {
        Self::with_optional_signer_and_anchor_config(
            portal_address,
            l1_provider,
            None,
            anchor_config,
        )
    }

    /// Create a batch submitter that signs settlement certificates locally.
    pub fn with_signer_and_anchor_config(
        portal_address: Address,
        l1_provider: DynProvider<Ethereum>,
        signer: PrivateKeySigner,
        anchor_config: BatchAnchorConfig,
    ) -> Self {
        Self::with_optional_signer_and_anchor_config(
            portal_address,
            l1_provider,
            Some(signer),
            anchor_config,
        )
    }

    pub(crate) fn with_optional_signer_and_anchor_config(
        portal_address: Address,
        l1_provider: DynProvider<Ethereum>,
        signer: Option<PrivateKeySigner>,
        anchor_config: BatchAnchorConfig,
    ) -> Self {
        let portal = SpherePortal::new(portal_address, l1_provider.clone());
        Self {
            portal_address,
            l1_provider,
            portal,
            stable_portal_metadata: OnceLock::new(),
            signer,
            l1_fetch_concurrency: 16,
            anchor_config,
            ancestry_header_cache: RwLock::new(LruMap::new(ByLength::new(
                DEFAULT_ANCESTRY_HEADER_CACHE_CAPACITY,
            ))),
        }
    }

    /// Resolve the single immutable anchor shared by proving, quorum, and submission.
    pub async fn prepare_batch(&self, batch: BatchData) -> Result<PreparedBatch> {
        let anchor = self.resolve_batch_anchor(batch.arc_block_number).await?;
        Ok(PreparedBatch { batch, anchor })
    }

    pub async fn submit_batch(
        &self,
        prepared: &PreparedBatch,
        certificate: Option<&SettlementCertificate>,
        verifier_mode: VerifierMode,
    ) -> std::result::Result<BatchSubmitted, BatchSubmitError> {
        let batch = &prepared.batch;
        let (verifier_config, proof) = settlement_proof(verifier_mode, None)?;
        let block_transition = BlockTransition {
            prevBlockHash: batch.prev_block_hash,
            nextBlockHash: batch.next_block_hash,
        };
        let deposit_transition = DepositQueueTransition {
            prevProcessedHash: batch.prev_processed_deposit_hash,
            nextProcessedHash: batch.next_processed_deposit_hash,
            prevDepositNumber: batch.prev_deposit_number,
            nextDepositNumber: batch.next_deposit_number,
        };
        let token_transition = TokenEnablementTransition {
            prevProcessedTokenCount: batch.prev_processed_token_count,
            nextProcessedTokenCount: batch.next_processed_token_count,
        };

        let signer = self.signer.as_ref();
        let metadata = self
            .read_submission_metadata(signer.map_or(Address::ZERO, PrivateKeySigner::address))
            .await?;
        self.validate_submission_metadata(batch, metadata, certificate.is_some())?;
        if let Some(certificate) = certificate {
            self.validate_certificate(
                prepared,
                batch.sphere_height,
                metadata,
                verifier_mode,
                certificate,
            )?;
        }
        let current_l1_block = self.validate_prepared_anchor(prepared).await?;
        let recent_arc_block_number = prepared.anchor.recent_block_number();
        // EIP-2935 exposes hash(N) starting in N+1. A transaction built after observing head N
        // cannot land before N+1, so anchoring to the current tip is valid at execution time.
        let anchor_block_number = prepared.anchor_block_number();
        let anchor_block_hash = prepared.anchor.block_hash();
        let anchors_to_current_tip = anchor_block_number == current_l1_block;

        let signatures = if let Some(certificate) = certificate {
            certificate.signatures.clone()
        } else {
            // Legacy mode, where the 1-of-1 sequencer will self-sign the attestation
            let signer =
                signer.ok_or_eyre("batch submission requires the local sequencer signer")?;
            if !metadata.signer_is_sequencer {
                return Err(eyre::eyre!(
                    "local sequencer signer {} is not active in the portal sequencer set",
                    signer.address()
                )
                .into());
            }
            vec![self.sign_settlement_attestation(
                signer,
                metadata,
                SettlementAttestationInput {
                    batch,
                    anchor_block_number,
                    anchor_block_hash,
                    block_transition: &block_transition,
                    deposit_transition: &deposit_transition,
                    verifier_config: &verifier_config,
                },
            )?]
        };
        let mut submission = self.portal.submitBatch_1(
            batch.arc_block_number,
            recent_arc_block_number,
            block_transition,
            deposit_transition,
            token_transition,
            batch.withdrawal_queue_hash,
            verifier_config,
            proof,
            U256::from(batch.sphere_height),
            signatures,
        );
        if anchors_to_current_tip {
            submission = submission.gas(SUBMIT_BATCH_GAS_LIMIT);
        }
        let _guard = L1_SUBMISSION_LOCK.lock().await;
        let sender = signer.ok_or_eyre("batch submission requires the local sequencer signer")?;
        let nonce = self
            .l1_provider
            .get_transaction_count(sender.address())
            .pending()
            .await
            .map_err(|error| BatchSubmitError::Other(error.into()))?;
        let submission = submission.nonce(nonce);
        let receipt = tokio::time::timeout(Duration::from_secs(30), async {
            let pending = submission.send().await?;
            Ok::<_, eyre::Report>(pending.get_receipt().await?)
        })
        .await
        .map_err(|_| eyre::eyre!("submitBatch submission timed out after 30 seconds"))??;
        let tx_hash = receipt.transaction_hash();
        if !receipt.status() {
            return Err(
                eyre::eyre!("submitBatch tx {tx_hash} was included but reverted on L1").into(),
            );
        }

        let event = self.decode_batch_submitted(receipt.logs())?;

        info!(
            %tx_hash,
            withdrawal_batch_index = event.withdrawalBatchIndex,
            withdrawal_queue_index = %event.withdrawalQueueIndex,
            "Batch submitted to L1"
        );

        Ok(event)
    }

    fn sign_settlement_attestation(
        &self,
        signer: &PrivateKeySigner,
        metadata: PortalSubmissionMetadata,
        attestation: SettlementAttestationInput<'_>,
    ) -> Result<Bytes> {
        let SettlementAttestationInput {
            batch,
            anchor_block_number,
            anchor_block_hash,
            block_transition,
            deposit_transition,
            verifier_config,
        } = attestation;
        let domain = AttestationDomain {
            l1_chain_id: metadata.stable.chain_id,
            portal_address: self.portal_address,
            sphere_id: metadata.stable.sphere_id,
        };
        let message = SettlementAttestation {
            sphereId: metadata.stable.sphere_id,
            sequencerSetVersion: metadata.sequencer_set_version,
            sphereHeight: U256::from(batch.sphere_height),
            withdrawalBatchIndex: U256::from(batch.withdrawal_batch_index),
            verifier: metadata.verifier,
            arcBlockNumber: batch.arc_block_number,
            anchorBlockNumber: anchor_block_number,
            anchorBlockHash: anchor_block_hash,
            blockTransitionHash: keccak256(block_transition.abi_encode()),
            depositQueueTransitionHash: keccak256(deposit_transition.abi_encode()),
            tokenEnablementTransitionHash: token_transition_hash(
                batch.prev_processed_token_count,
                batch.next_processed_token_count,
            ),
            withdrawalQueueHash: batch.withdrawal_queue_hash,
            verifierConfigHash: keccak256(verifier_config),
        };
        Ok(SignedSettlementAttestation::sign(message, domain, signer)?.signature)
    }

    /// Read all mutable portal state needed for one submission at a single L1 block.
    ///
    /// The portal and chain identifiers are immutable, so the first call includes and caches them.
    /// Sequencer membership and verifier configuration are deliberately refreshed on every submission.
    async fn read_submission_metadata(&self, signer: Address) -> Result<PortalSubmissionMetadata> {
        if let Some(stable) = self.stable_portal_metadata.get().copied() {
            let (
                withdrawal_batch_index,
                sequencer_set_version,
                sequencer_threshold,
                signer_is_sequencer,
                verifier,
            ) = self
                .l1_provider
                .multicall()
                .add(self.portal.withdrawalBatchIndex())
                .add(self.portal.sequencerSetVersion())
                .add(self.portal.sequencerThreshold())
                .add(self.portal.isSequencer(signer))
                .add(self.portal.verifier())
                .aggregate()
                .await?;
            return Ok(Self::build_submission_metadata(
                RawPortalSubmissionMetadata {
                    withdrawal_batch_index,
                    sequencer_set_version,
                    sequencer_threshold,
                    signer_is_sequencer,
                    verifier,
                },
                stable,
            ));
        }

        let (
            withdrawal_batch_index,
            sequencer_set_version,
            sequencer_threshold,
            signer_is_sequencer,
            verifier,
            sphere_id,
            chain_id,
        ) = self
            .l1_provider
            .multicall()
            .add(self.portal.withdrawalBatchIndex())
            .add(self.portal.sequencerSetVersion())
            .add(self.portal.sequencerThreshold())
            .add(self.portal.isSequencer(signer))
            .add(self.portal.verifier())
            .add(self.portal.sphereId())
            .get_chain_id()
            .aggregate()
            .await?;
        let stable = StablePortalMetadata {
            sphere_id,
            chain_id: chain_id
                .try_into()
                .map_err(|_| eyre::eyre!("Arc L1 chain ID overflow"))?,
        };
        let _ = self.stable_portal_metadata.set(stable);
        Ok(Self::build_submission_metadata(
            RawPortalSubmissionMetadata {
                withdrawal_batch_index,
                sequencer_set_version,
                sequencer_threshold,
                signer_is_sequencer,
                verifier,
            },
            stable,
        ))
    }

    fn build_submission_metadata(
        raw: RawPortalSubmissionMetadata,
        stable: StablePortalMetadata,
    ) -> PortalSubmissionMetadata {
        PortalSubmissionMetadata {
            withdrawal_batch_index: raw.withdrawal_batch_index,
            stable,
            sequencer_set_version: raw.sequencer_set_version,
            sequencer_threshold: raw.sequencer_threshold,
            signer_is_sequencer: raw.signer_is_sequencer,
            verifier: raw.verifier,
        }
    }

    fn validate_submission_metadata(
        &self,
        batch: &BatchData,
        metadata: PortalSubmissionMetadata,
        has_certificate: bool,
    ) -> Result<()> {
        let expected_l2_index = metadata
            .withdrawal_batch_index
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("portal withdrawal batch index overflow"))?;
        eyre::ensure!(
            batch.withdrawal_batch_index == expected_l2_index,
            "withdrawal batch index mismatch for sphere block {}: L2 finalized index {}, expected portal index + 1 ({expected_l2_index})",
            batch.sphere_height,
            batch.withdrawal_batch_index,
        );
        eyre::ensure!(
            metadata.sequencer_threshold > 0,
            "portal sequencer threshold is zero"
        );
        if !has_certificate {
            eyre::ensure!(
                metadata.sequencer_threshold == 1,
                "local certificate signing requires a 1-of-1 sequencer set; portal threshold is {}",
                metadata.sequencer_threshold
            );
        }
        Ok(())
    }

    /// Decode the `BatchSubmitted` event from a confirmed `submitBatch` receipt's logs.
    fn decode_batch_submitted(&self, logs: &[alloy_rpc_types_eth::Log]) -> Result<BatchSubmitted> {
        logs.iter()
            .filter(|log| log.address() == self.portal_address)
            .find_map(|log| decode_batch_submitted_log(&log.inner))
            .transpose()?
            .ok_or_else(|| {
                eyre::eyre!("confirmed submitBatch receipt is missing the BatchSubmitted event")
            })
    }

    /// Validate that a collected certificate commits to the exact calldata this submitter will
    /// send, and derive the anchor mode from the signed statement instead of recomputing it.
    fn validate_certificate(
        &self,
        prepared: &PreparedBatch,
        sphere_height: u64,
        metadata: PortalSubmissionMetadata,
        verifier_mode: VerifierMode,
        certificate: &SettlementCertificate,
    ) -> Result<()> {
        let batch = &prepared.batch;
        if certificate.height != sphere_height {
            return Err(eyre::eyre!(
                "settlement certificate height {} does not match batch height {sphere_height}",
                certificate.height
            ));
        }
        let attestation = &certificate.attestation;

        let expected_block_transition_hash = alloy_primitives::keccak256(
            (batch.prev_block_hash, batch.next_block_hash).abi_encode(),
        );
        let expected_deposit_transition_hash = alloy_primitives::keccak256(
            (
                batch.prev_processed_deposit_hash,
                batch.next_processed_deposit_hash,
                batch.prev_deposit_number,
                batch.next_deposit_number,
            )
                .abi_encode(),
        );
        let expected_token_transition_hash = token_transition_hash(
            batch.prev_processed_token_count,
            batch.next_processed_token_count,
        );

        // Run a bunch of checks to verify that whats in the attestation certificate is exactly what
        // we expect. `submitBatch` will revert if any of these are wrong, so we should catch it early.
        eyre::ensure!(
            attestation.sphereId == metadata.stable.sphere_id,
            "certificate sphere ID changed"
        );
        eyre::ensure!(
            attestation.sequencerSetVersion == metadata.sequencer_set_version,
            "certificate signer-set version changed"
        );
        eyre::ensure!(
            attestation.sphereHeight == U256::from(sphere_height),
            "certificate sphere height changed"
        );
        eyre::ensure!(
            attestation.withdrawalBatchIndex == U256::from(batch.withdrawal_batch_index),
            "certificate withdrawal batch index changed"
        );
        eyre::ensure!(
            attestation.verifier == metadata.verifier,
            "certificate verifier changed"
        );
        eyre::ensure!(
            attestation.arcBlockNumber == batch.arc_block_number,
            "certificate Arc block changed"
        );
        eyre::ensure!(
            attestation.blockTransitionHash == expected_block_transition_hash,
            "certificate block transition changed"
        );
        eyre::ensure!(
            attestation.depositQueueTransitionHash == expected_deposit_transition_hash,
            "certificate deposit transition changed"
        );
        eyre::ensure!(
            attestation.tokenEnablementTransitionHash == expected_token_transition_hash,
            "certificate token transition changed"
        );
        eyre::ensure!(
            attestation.withdrawalQueueHash == batch.withdrawal_queue_hash,
            "certificate withdrawal queue hash changed"
        );
        eyre::ensure!(
            VerifierMode::try_from(attestation.verifierConfigHash)? == verifier_mode,
            "certificate verifier config changed"
        );
        eyre::ensure!(
            attestation.anchorBlockNumber == prepared.anchor_block_number(),
            "certificate anchor block changed"
        );
        eyre::ensure!(
            attestation.anchorBlockHash == prepared.anchor.block_hash(),
            "certificate anchor hash changed"
        );

        Ok(())
    }

    /// Resolve the anchor mode for the given `arc_block_number`.
    ///
    /// - **Direct** (gap < configured effective window): the portal reads the
    ///   hash directly from EIP-2935.
    /// - **Ancestry** (gap ≥ configured effective window): a recent L1 block
    async fn resolve_batch_anchor(&self, arc_block_number: u64) -> Result<BatchAnchor> {
        let current_l1_block = wait_for_l1_block(&self.l1_provider, arc_block_number).await?;

        let gap = current_l1_block.saturating_sub(arc_block_number);

        if gap < self.anchor_config.effective_window() {
            // The cache is only useful during ancestry recovery. Replace it
            // instead of clearing it so the hash table's allocation is freed.
            let has_cached_headers = !self.ancestry_header_cache.read().is_empty();
            if has_cached_headers {
                *self.ancestry_header_cache.write() =
                    LruMap::new(ByLength::new(DEFAULT_ANCESTRY_HEADER_CACHE_CAPACITY));
            }
            let block_hash = self
                .l1_provider
                .get_header_by_number(arc_block_number.into())
                .await?
                .ok_or_eyre(format!("L1 anchor block {arc_block_number} not found"))?
                .hash;
            return Ok(BatchAnchor::Direct { block_hash });
        }

        let anchor_block = current_l1_block.saturating_sub(self.anchor_config.safety_margin());
        let ancestry_headers = self
            .fetch_ancestry_headers(arc_block_number, anchor_block)
            .await?;

        warn!(
            arc_block_number,
            current_l1_block,
            anchor_block,
            gap,
            header_count = ancestry_headers.len(),
            total_bytes = ancestry_headers.iter().map(|h| h.len()).sum::<usize>(),
            "arc_block_number outside EIP-2935 effective window, using ancestry mode"
        );

        let block_hash = self
            .l1_provider
            .get_header_by_number(anchor_block.into())
            .await?
            .ok_or_eyre(format!("L1 anchor block {anchor_block} not found"))?
            .hash;
        Ok(BatchAnchor::Ancestry {
            block_number: anchor_block,
            block_hash,
            ancestry_headers,
        })
    }

    async fn validate_prepared_anchor(
        &self,
        prepared: &PreparedBatch,
    ) -> std::result::Result<u64, BatchSubmitError> {
        let anchor = &prepared.anchor;
        let anchor_block_number = prepared.anchor_block_number();
        if anchor_block_number < prepared.batch.arc_block_number {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor predates the batch Arc block"
            )));
        }

        let current_l1_block = wait_for_l1_block(&self.l1_provider, anchor_block_number).await?;
        if current_l1_block.saturating_sub(anchor_block_number)
            >= self.anchor_config.history_window()
        {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor block fell outside the EIP-2935 history window"
            )));
        }

        let canonical = self
            .l1_provider
            .get_header_by_number(anchor_block_number.into())
            .await
            .map_err(|error| BatchSubmitError::Other(error.into()))?
            .ok_or_else(|| {
                BatchSubmitError::Other(eyre::eyre!(
                    "prepared L1 anchor block {} not found",
                    anchor_block_number
                ))
            })?;
        if canonical.hash != anchor.block_hash() {
            return Err(BatchSubmitError::PreparedAnchorInvalid(eyre::eyre!(
                "prepared L1 anchor hash is no longer canonical"
            )));
        }
        Ok(current_l1_block)
    }

    /// Fetch and RLP-encode L1 block headers from `from + 1` to `to` (inclusive),
    /// validating the parent-hash chain and reusing cached overlapping headers.
    ///
    /// Returns headers in ascending block-number order. The first header's
    /// `parent_hash` is validated against the hash of block `from`, ensuring the
    /// chain is rooted at the expected block.
    async fn fetch_ancestry_headers(&self, from: u64, to: u64) -> Result<Vec<Bytes>> {
        use futures::stream;

        if to <= from {
            return Ok(Vec::new());
        }

        // Snapshot the cache without changing its LRU order. Network requests
        // and validation happen after the read lock is released.
        let (cached, missing) = {
            let cache = self.ancestry_header_cache.read();
            let mut cached = Vec::new();
            let mut missing = Vec::new();
            for block_number in from..=to {
                if let Some(header) = cache.peek(&block_number) {
                    cached.push((block_number, header.clone()));
                } else {
                    missing.push(block_number);
                }
            }
            (cached, missing)
        };
        let cache_hits = cached.len();

        // Fetch and encode only the cache misses.
        let fetched = stream::iter(missing.iter().copied())
            .map(|block_number| {
                let provider = &self.l1_provider;
                async move {
                    let header = provider
                        .get_header_by_number(block_number.into())
                        .await?
                        .ok_or_else(|| {
                            eyre::eyre!("L1 header not found for block {block_number}")
                        })?;
                    let header = header.inner;
                    let mut encoded = Vec::with_capacity(600);
                    header.encode(&mut encoded);
                    let cached_header = CachedAncestryHeader {
                        parent_hash: header.parent_hash,
                        hash: alloy_primitives::keccak256(&encoded),
                        encoded: Bytes::from(encoded),
                    };
                    Ok::<_, eyre::Report>((block_number, cached_header))
                }
            })
            .buffer_unordered(self.l1_fetch_concurrency)
            .try_collect::<Vec<_>>()
            .await?;

        // Pure resolution owns merging, ordering, completeness, duplicate, and
        // parent-hash validation. Do not mutate the cache unless it succeeds.
        let ResolvedAncestry {
            headers,
            fetched_headers,
        } = resolve_ancestry_headers(from, to, cached, fetched)?;
        let fetched_count = fetched_headers.len();

        // Commit only entries fetched from the snapshot's misses. Another task
        // may have filled one while the network requests were in flight.
        let mut cache = self.ancestry_header_cache.write();
        for (block_number, header) in fetched_headers {
            if let Some(existing) = cache.peek(&block_number) {
                if existing.hash != header.hash {
                    return Err(eyre::eyre!(
                        "conflicting L1 header at cached block {block_number}: \
                         cached={}, fetched={}",
                        existing.hash,
                        header.hash
                    ));
                }
                continue;
            }
            if !cache.insert(block_number, header) {
                return Err(eyre::eyre!(
                    "failed to cache L1 header for block {block_number}"
                ));
            }
        }

        info!(
            from,
            to,
            cache_hits,
            fetched = fetched_count,
            "resolved ancestry headers"
        );

        Ok(headers)
    }

    /// Read the current `blockHash` from the SpherePortal on L1.
    ///
    /// Used to reject a prepared batch whose predecessor no longer matches the
    /// portal before submitting it.
    pub async fn read_portal_block_hash(&self) -> Result<B256> {
        let hash = self.portal.blockHash().call().await?;
        Ok(hash)
    }
}
impl BatchSubmitter {
    /// Read the current withdrawal queue bounds in one Multicall3 request.
    async fn read_portal_withdrawal_queue_bounds(&self) -> Result<(u64, u64)> {
        let (head, tail) = self
            .l1_provider
            .multicall()
            .add(self.portal.withdrawalQueueHead())
            .add(self.portal.withdrawalQueueTail())
            .aggregate()
            .await?;
        Ok((
            head.try_into()
                .map_err(|_| eyre::eyre!("withdrawal queue head overflow"))?,
            tail.try_into()
                .map_err(|_| eyre::eyre!("withdrawal queue tail overflow"))?,
        ))
    }

    /// Re-populate one page of the in-memory [`WithdrawalStore`](crate::withdrawals::WithdrawalStore)
    /// after a sequencer restart or page refill.
    ///
    /// The L1 portal stores only hash chains, not the actual [`Withdrawal`](abi::Withdrawal)
    /// structs. This method reconstructs them by:
    ///
    /// 1. Reading `withdrawalQueueHead` / `withdrawalQueueTail` from the **L1 portal**
    ///    to determine which bounded page starts at the current head.
    /// 2. Querying the `BatchSubmitted` event for each slot in that page via the
    ///    indexed `withdrawalQueueIndex` topic.
    /// 3. Resolving each event's `nextBlockHash` to a **sphere L2** block number.
    /// 4. Fetching `WithdrawalRequested` events from the **sphere L2** outbox in
    ///    that block. A non-empty withdrawal batch is finalized in the same
    ///    sphere block as its requests.
    /// 5. Reading the head slot's current on-chain hash for partial processing
    ///    detection.
    /// 6. Verifying the hash chain and trimming already-processed withdrawals.
    ///
    /// Returns one bounded page of verified withdrawals starting at the portal head.
    #[instrument(skip_all, fields(portal = %self.portal_address))]
    pub async fn fetch_pending_withdrawals<P: SphereSequencerProvider>(
        &self,
        sphere_provider: &P,
        outbox_address: Address,
    ) -> Result<WithdrawalPage> {
        // Step 1: read pending slot range from the L1 portal and bound this recovery page.
        let (head, tail) = self.read_portal_withdrawal_queue_bounds().await?;
        let page_tail = tail.min(head.saturating_add(WITHDRAWAL_RECOVERY_PAGE_SIZE));

        if head >= tail {
            return Ok(WithdrawalPage {
                head,
                tail: head,
                batches: BTreeMap::new(),
            });
        }

        // Step 2: query BatchSubmitted events for this page [head, page_tail)
        // by their indexed withdrawalQueueIndex.
        let events = self.find_batch_events_by_index(head, page_tail).await?;

        // Step 3: resolve each L1 event's nextBlockHash to a sphere L2 block number.
        let mut sphere_block_by_slot: BTreeMap<u64, u64> = BTreeMap::new();
        for (&portal_slot, event) in &events {
            let block_number = sphere_provider
                .block_number(event.nextBlockHash)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "sphere block not found for hash {} (portal slot {portal_slot})",
                        event.nextBlockHash
                    )
                })?;
            sphere_block_by_slot.insert(portal_slot, block_number);
        }

        // Step 4: fetch WithdrawalRequested events from sphere L2 for each pending slot.
        let mut slot_withdrawals: BTreeMap<u64, Vec<abi::Withdrawal>> = BTreeMap::new();
        for portal_slot in head..page_tail {
            let Some(&sphere_block) = sphere_block_by_slot.get(&portal_slot) else {
                continue;
            };
            let withdrawals =
                fetch_slot_withdrawals(sphere_provider, outbox_address, sphere_block).await?;
            slot_withdrawals.insert(portal_slot, withdrawals);
        }

        // Step 5: read the head slot's current on-chain hash (for partial processing detection).
        let head_slot_hash = self
            .portal
            .withdrawalQueueSlot(U256::from(head))
            .call()
            .await?;

        // Guard: verify the queue didn't change during the multi-RPC replay.
        let (head2, tail2) = self.read_portal_withdrawal_queue_bounds().await?;

        if head2 != head || tail2 < page_tail {
            eyre::bail!(
                "withdrawal queue changed during page restore ({}..{} -> {}..{}), retry from the current head",
                head,
                tail,
                head2,
                tail2
            );
        }

        // Step 6: resolve all fetched data into verified withdrawal sets.
        resolve_pending_slots(head, page_tail, &events, &slot_withdrawals, head_slot_hash).map(
            |batches| WithdrawalPage {
                head,
                tail: tail2,
                batches,
            },
        )
    }

    /// Fetch `BatchSubmitted` events for logical queue indices `[first_index, tail)`
    /// by walking L1 backwards in chunks while filtering by the indexed
    /// `withdrawalQueueIndex` topic. Logical queue indices never repeat
    /// (head/tail are non-wrapping counters), so the topic filter identifies
    /// each batch exactly without positional counting.
    async fn find_batch_events_by_index(
        &self,
        first_index: u64,
        tail: u64,
    ) -> Result<BTreeMap<u64, BatchSubmitted>> {
        if first_index >= tail {
            return Ok(BTreeMap::new());
        }

        let index_topics: Vec<B256> = (first_index..tail)
            .map(|index| B256::from(U256::from(index)))
            .collect();
        let needed = index_topics.len();

        let mut found = BTreeMap::new();
        let mut hi = self.l1_provider.get_block_number().await?;

        while found.len() < needed {
            let lo = backward_log_query_start(hi, 0);

            let filter = Filter::new()
                .address(self.portal_address)
                .event_signature(vec![
                    BatchSubmitted::SIGNATURE_HASH,
                    LegacyBatchSubmitted::SIGNATURE_HASH,
                ])
                .topic2(index_topics.clone())
                .from_block(lo)
                .to_block(hi);
            let events = self.l1_provider.get_logs(&filter).await?;

            for log in events {
                let event = decode_batch_submitted_log(&log.inner)
                    .transpose()?
                    .ok_or_else(|| eyre::eyre!("unexpected event in BatchSubmitted query"))?;
                let index: u64 = event.withdrawalQueueIndex.try_into().map_err(|_| {
                    eyre::eyre!("withdrawal queue index overflow in BatchSubmitted")
                })?;
                if found.insert(index, event).is_some() {
                    eyre::bail!("duplicate BatchSubmitted event for portal queue index {index}");
                }
            }

            if lo == 0 {
                break;
            }
            hi = lo - 1;
        }

        Ok(found)
    }
}

fn decode_batch_submitted_log(log: &alloy_primitives::Log) -> Option<Result<BatchSubmitted>> {
    match log.topics().first() {
        Some(topic) if topic == &BatchSubmitted::SIGNATURE_HASH => Some(
            BatchSubmitted::decode_log(log)
                .map(|event| event.data)
                .map_err(Into::into),
        ),
        Some(topic) if topic == &LegacyBatchSubmitted::SIGNATURE_HASH => Some(
            LegacyBatchSubmitted::decode_log(log)
                .map(|event| BatchSubmitted {
                    withdrawalBatchIndex: event.withdrawalBatchIndex,
                    withdrawalQueueIndex: event.withdrawalQueueIndex,
                    nextProcessedDepositQueueHash: event.nextProcessedDepositQueueHash,
                    nextBlockHash: event.nextBlockHash,
                    withdrawalQueueHash: event.withdrawalQueueHash,
                    lastProcessedDepositNumber: event.lastProcessedDepositNumber,
                    lastProcessedEnabledTokenCount: 0,
                })
                .map_err(Into::into),
        ),
        _ => None,
    }
}
/// Hash the token transition exactly as the selected settlement statement expects.
pub fn token_transition_hash(previous: u64, next: u64) -> B256 {
    keccak256((previous, next).abi_encode())
}

/// Data required to submit a single batch to the SpherePortal on L1.
///
/// Produced by the sphere monitor and combined with one [`BatchAnchor`] in [`PreparedBatch`].
#[derive(Debug, Clone)]
pub struct BatchData {
    /// Sphere L2 height committed by this batch.
    pub sphere_height: u64,
    /// Arc L1 block number for EIP-2935 verification.
    pub arc_block_number: u64,
    /// Previous sphere block hash (must match portal's current `blockHash`).
    pub prev_block_hash: B256,
    /// New sphere block hash after this batch.
    pub next_block_hash: B256,
    /// Deposit queue: where the sphere started processing.
    pub prev_processed_deposit_hash: B256,
    /// Deposit queue: where the sphere processed up to.
    pub next_processed_deposit_hash: B256,
    /// Deposit counter at the start of processing.
    pub prev_deposit_number: u64,
    /// Deposit counter after processing.
    pub next_deposit_number: u64,
    /// Enabled-token prefix at the start of the batch.
    pub prev_processed_token_count: u64,
    /// Enabled-token prefix after the batch.
    pub next_processed_token_count: u64,
    /// Withdrawal queue hash for this batch (`B256::ZERO` if no withdrawals).
    pub withdrawal_queue_hash: B256,
    /// L2 withdrawal batch index validated against the portal before submission.
    pub withdrawal_batch_index: u64,
}

/// Immutable Arc anchor selected for one settlement attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchAnchor {
    /// The batch's Arc block remains directly available through EIP-2935.
    Direct {
        /// Canonical hash of `BatchData::arc_block_number` at preparation time.
        block_hash: B256,
    },
    /// A recent L1 block anchors a parent-linked header chain from the batch's Arc block.
    Ancestry {
        /// Recent L1 block number whose hash the portal passes to the verifier.
        block_number: u64,
        /// Canonical hash of `block_number` at preparation time.
        block_hash: B256,
        /// Headers from `BatchData::arc_block_number + 1` through `block_number`.
        ancestry_headers: Vec<Bytes>,
    },
}

impl BatchAnchor {
    /// Returns the L1 block whose hash the portal passes to the verifier.
    pub const fn block_number(&self, arc_block_number: u64) -> u64 {
        match self {
            Self::Direct { .. } => arc_block_number,
            Self::Ancestry { block_number, .. } => *block_number,
        }
    }

    /// Returns the canonical hash of the selected anchor block.
    pub const fn block_hash(&self) -> B256 {
        match self {
            Self::Direct { block_hash } | Self::Ancestry { block_hash, .. } => *block_hash,
        }
    }

    /// Returns the prepared ancestry headers, empty in direct mode.
    pub fn ancestry_headers(&self) -> &[Bytes] {
        match self {
            Self::Direct { .. } => &[],
            Self::Ancestry {
                ancestry_headers, ..
            } => ancestry_headers,
        }
    }

    /// Returns the `recentArcBlockNumber` argument for `submitBatch`.
    pub const fn recent_block_number(&self) -> u64 {
        match self {
            Self::Direct { .. } => 0,
            Self::Ancestry { block_number, .. } => *block_number,
        }
    }

    const fn mode_name(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Ancestry { .. } => "ancestry",
        }
    }
}

/// Batch commitments and their single authoritative Arc anchor.
#[derive(Debug, Clone)]
pub struct PreparedBatch {
    pub batch: BatchData,
    pub anchor: BatchAnchor,
}

impl PreparedBatch {
    /// Returns the L1 block whose hash the portal passes to the verifier.
    pub const fn anchor_block_number(&self) -> u64 {
        self.anchor.block_number(self.batch.arc_block_number)
    }
}
struct SettlementAttestationInput<'a> {
    batch: &'a BatchData,
    anchor_block_number: u64,
    anchor_block_hash: B256,
    block_transition: &'a BlockTransition,
    deposit_transition: &'a DepositQueueTransition,
    verifier_config: &'a Bytes,
}

#[derive(Debug, Clone, Copy)]
struct StablePortalMetadata {
    sphere_id: u32,
    chain_id: u64,
}

struct RawPortalSubmissionMetadata {
    withdrawal_batch_index: u64,
    sequencer_set_version: u64,
    sequencer_threshold: u8,
    signer_is_sequencer: bool,
    verifier: Address,
}

#[derive(Debug, Clone, Copy)]
struct PortalSubmissionMetadata {
    withdrawal_batch_index: u64,
    stable: StablePortalMetadata,
    sequencer_set_version: u64,
    sequencer_threshold: u8,
    signer_is_sequencer: bool,
    verifier: Address,
}
/// One validated L1 header retained for ancestry proof construction.
#[derive(Debug, Clone)]
struct CachedAncestryHeader {
    parent_hash: B256,
    hash: B256,
    encoded: Bytes,
}

/// A complete, ordered, parent-linked ancestry range.
///
/// `headers` excludes the base block at `from`; `fetched_headers` contains only
/// entries that the caller should commit to the cache after resolution succeeds.
#[derive(Debug)]
struct ResolvedAncestry {
    headers: Vec<Bytes>,
    fetched_headers: Vec<(u64, CachedAncestryHeader)>,
}

/// Merge cached and fetched headers into one validated ancestry range.
fn resolve_ancestry_headers(
    from: u64,
    to: u64,
    cached: Vec<(u64, CachedAncestryHeader)>,
    fetched: Vec<(u64, CachedAncestryHeader)>,
) -> Result<ResolvedAncestry> {
    debug_assert!(from < to, "caller skips empty ancestry ranges");

    let range_len = (to - from + 1) as usize;
    let fetched_count = fetched.len();
    let mut merged = vec![None; range_len];

    let mut insert = |block_number, header, was_fetched| -> Result<()> {
        if !(from..=to).contains(&block_number) {
            return Err(eyre::eyre!(
                "received out-of-range L1 header for block {block_number}; expected {from}..={to}"
            ));
        }
        let index = (block_number - from) as usize;
        if merged[index].replace((header, was_fetched)).is_some() {
            return Err(eyre::eyre!(
                "received duplicate L1 header for block {block_number}"
            ));
        }
        Ok(())
    };
    for (block_number, header) in cached {
        insert(block_number, header, false)?;
    }
    for (block_number, header) in fetched {
        insert(block_number, header, true)?;
    }

    let mut merged = merged.into_iter();
    let (base, base_was_fetched) = merged
        .next()
        .flatten()
        .ok_or_else(|| eyre::eyre!("L1 header not found for base block {from}"))?;
    let mut parent_hash = base.hash;
    let mut headers = Vec::with_capacity(range_len - 1);
    let mut fetched_headers = Vec::with_capacity(fetched_count);
    if base_was_fetched {
        fetched_headers.push((from, base));
    }

    for (block_number, entry) in ((from + 1)..=to).zip(merged) {
        let (header, was_fetched) =
            entry.ok_or_else(|| eyre::eyre!("L1 header not found for block {block_number}"))?;
        if header.parent_hash != parent_hash {
            return Err(eyre::eyre!(
                "parent-hash chain broken at block {block_number}: \
                 expected parent_hash={parent_hash}, got={}",
                header.parent_hash
            ));
        }
        parent_hash = header.hash;
        headers.push(header.encoded.clone());
        if was_fetched {
            fetched_headers.push((block_number, header));
        }
    }

    Ok(ResolvedAncestry {
        headers,
        fetched_headers,
    })
}

pub fn settlement_proof(
    verifier_mode: VerifierMode,
    proof_bundle: Option<&ProofBundle>,
) -> Result<(Bytes, Bytes)> {
    let config = Bytes::from_static(verifier_mode.config());
    let Some(bundle) = proof_bundle else {
        return Ok((config, Bytes::new()));
    };
    eyre::ensure!(
        VerifierMode::try_from(bundle.verifier_config.as_ref())? == verifier_mode,
        "proof bundle verifier mode does not match requested mode"
    );
    verifier_mode.validate_proof_shape(&bundle.proof)?;
    Ok((config, bundle.proof.clone()))
}

/// Returns the L1 RPC tip once it reaches `block_number`.
///
/// The Sphere builds on L1 blocks from its own subscription, so `eth_blockNumber` can trail the
/// block a batch anchors to for a few hundred milliseconds. Errors if the RPC fails or has not
/// reached `block_number` within `L1_CATCH_UP_TIMEOUT`.
pub(crate) async fn wait_for_l1_block(
    l1_provider: &DynProvider<Ethereum>,
    block_number: u64,
) -> Result<u64> {
    let deadline = Instant::now() + L1_CATCH_UP_TIMEOUT;
    loop {
        let tip = l1_provider.get_block_number().await?;
        if tip >= block_number {
            return Ok(tip);
        }
        ensure!(
            Instant::now() < deadline,
            "L1 block {block_number} is not yet confirmed on L1 (tip={tip})"
        );
        sleep(L1_CATCH_UP_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::ProviderBuilder;
    use alloy_transport::mock::Asserter;
    fn mock_l1(asserter: Asserter) -> DynProvider<Ethereum> {
        ProviderBuilder::new_with_network::<Ethereum>()
            .connect_mocked_client(asserter)
            .erased()
    }

    #[tokio::test(start_paused = true)]
    async fn anchor_resolution_waits_for_lagging_l1_tip() {
        let asserter = Asserter::new();
        let submitter = BatchSubmitter::new(Address::ZERO, mock_l1(asserter.clone()));

        let header = alloy_rpc_types_eth::Header::new(alloy_consensus::Header {
            number: 101,
            ..Default::default()
        });
        let hash = header.hash;
        asserter.push_success(&100_u64);
        asserter.push_success(&101_u64);
        asserter.push_success(&header);
        let started = Instant::now();
        let anchor = submitter.resolve_batch_anchor(101).await.unwrap();

        assert_eq!(anchor.block_hash(), hash);
        assert_eq!(started.elapsed(), L1_CATCH_UP_POLL_INTERVAL);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn anchor_resolution_rejects_l1_block_after_catch_up_timeout() {
        let asserter = Asserter::new();
        let submitter = BatchSubmitter::new(Address::ZERO, mock_l1(asserter.clone()));

        let polls = L1_CATCH_UP_TIMEOUT.as_millis() / L1_CATCH_UP_POLL_INTERVAL.as_millis() + 1;
        for _ in 0..polls {
            asserter.push_success(&100_u64);
        }
        let err = match submitter.resolve_batch_anchor(101).await {
            Ok(_) => panic!("future L1 anchor was accepted"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "L1 block 101 is not yet confirmed on L1 (tip=100)"
        );
        assert!(asserter.read_q().is_empty());
    }

    #[test]
    fn settlement_proof_enforces_verifier_mode_shape() {
        let (verifier_config, proof) = settlement_proof(VerifierMode::NoProof, None).unwrap();
        assert_eq!(verifier_config.as_ref(), &[2]);
        assert!(proof.is_empty());

        let nonempty_no_proof = ProofBundle {
            verifier_config: Bytes::from_static(VerifierMode::NoProof.config()),
            proof: Bytes::from_static(&[0xaa]),
        };
        assert!(settlement_proof(VerifierMode::NoProof, Some(&nonempty_no_proof)).is_err());
    }
}
/// Maximum number of pending withdrawal slots reconstructed in one recovery page.
/// Bounds L1 topic filters and arbitrary withdrawal data without limiting the on-chain FIFO.
pub(crate) const WITHDRAWAL_RECOVERY_PAGE_SIZE: u64 = 100;

/// Maximum block span for one bounded log query.
///
/// Native Sphere reads no longer use this limit; it remains the bound for L1 portal log recovery.
pub(crate) const LOG_QUERY_BLOCK_CHUNK: u64 = 5_000;

/// Longest wait for the L1 RPC to serve a block the Sphere already imported from its L1 subscription.
const L1_CATCH_UP_TIMEOUT: Duration = Duration::from_secs(2);

/// Interval between L1 tip reads while waiting for the RPC to catch up.
const L1_CATCH_UP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Canonical local identity of the Sphere block most recently accepted by the L1 portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalSphereAnchor {
    pub block_hash: B256,
    pub block_number: u64,
}

/// Read the L1 portal tip and resolve it against the local canonical Sphere chain.
///
/// A zero portal hash denotes genesis only when the portal's Sphere height is also zero. A non-zero
/// hash must be present locally at exactly the portal's Sphere height; silently treating an inconsistent checkpoint or a missing hash as
/// genesis could replay already-submitted history and construct an invalid transition from state
/// that the portal has superseded.
pub async fn resolve_portal_sphere_anchor<P>(
    sphere_provider: &P,
    portal_address: Address,
    l1_provider: &DynProvider<Ethereum>,
) -> Result<PortalSphereAnchor>
where
    P: BlockNumReader,
{
    let portal = SpherePortal::new(portal_address, l1_provider);
    // Read both fields from the same L1 state so a concurrent submission cannot mix checkpoints.
    let (block_hash, sphere_height) = l1_provider
        .multicall()
        .add(portal.blockHash())
        .add(portal.sphereHeight())
        .aggregate()
        .await
        .wrap_err("failed to read SpherePortal checkpoint")?;

    let block_number = if block_hash.is_zero() {
        eyre::ensure!(
            sphere_height.is_zero(),
            "inconsistent SpherePortal checkpoint: zero block hash at nonzero Sphere height {sphere_height}"
        );
        0
    } else {
        let block_number = sphere_provider
            .block_number(block_hash)?
            .ok_or_eyre(format!(
                "portal block hash {block_hash} is not canonical in the Sphere node"
            ))?;
        eyre::ensure!(
            U256::from(block_number) == sphere_height,
            "inconsistent SpherePortal checkpoint: block hash {block_hash} is local Sphere block {block_number}, but portal Sphere height is {sphere_height}"
        );
        block_number
    };

    Ok(PortalSphereAnchor {
        block_hash,
        block_number,
    })
}

/// Verified bounded window of the portal withdrawal queue reconstructed from chain history.
#[derive(Debug)]
pub struct WithdrawalPage {
    /// Portal head observed before reconstructing the page.
    pub head: u64,
    /// Portal tail observed after reconstruction was validated.
    pub tail: u64,
    /// Verified payloads keyed by logical portal queue index.
    pub batches: BTreeMap<u64, Vec<abi::Withdrawal>>,
}
/// One L2 withdrawal batch finalized by `SphereOutbox`.
#[derive(Debug, Clone)]
pub(crate) struct FinalizedBatch {
    /// Authoritative hash emitted by `BatchFinalized` and stored in `lastBatch()`.
    pub finalized_hash: B256,
    /// Authoritative L2 withdrawal batch index emitted by `BatchFinalized`.
    pub finalized_index: u64,
    /// Reconstructed withdrawal payloads for the off-chain processor store.
    pub withdrawals: Vec<abi::Withdrawal>,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizedBatchLog {
    pub(crate) block_number: u64,
    tx_index: u64,
    log_index: u64,
    tx_hash: B256,
    withdrawal_queue_hash: B256,
    withdrawal_batch_index: u64,
}

/// Sphere L2 state read at a specific block, used to populate [`BatchData`].
pub(crate) struct SphereBlockSnapshot {
    /// Latest Arc L1 block number as seen by the sphere.
    pub arc_block_number: u64,
    /// Cumulative hash of all deposits processed by the sphere up to this block.
    pub processed_deposit_hash: B256,
    /// Total number of deposits processed by the sphere up to this block.
    pub processed_deposit_number: u64,
    /// Number of portal token enablements processed by the sphere.
    pub processed_token_count: u64,
    /// Sphere L2 block hash.
    pub block_hash: B256,
}

/// Pure function that resolves pre-fetched data into verified withdrawal sets
/// ready to be stored.
///
/// For each pending portal slot in `[head, tail)`:
/// 1. Skips slots with no `BatchSubmitted` event or no fetched withdrawals.
/// 2. Verifies the hash chain of fetched withdrawals matches the L1 event's
///    `withdrawalQueueHash`.
/// 3. For the head slot, trims already-processed withdrawals using
///    `head_slot_hash` (the current on-chain slot hash). The L1 portal
///    processes withdrawals one-by-one, updating the slot hash after each.
///    If the sequencer crashed mid-slot, some are already consumed but `head`
///    hasn't advanced yet.
/// 4. Non-head slots are always fully unprocessed.
///
/// Returns a map of portal_slot → verified withdrawals to store.
fn resolve_pending_slots(
    head: u64,
    tail: u64,
    events: &BTreeMap<u64, BatchSubmitted>,
    slot_withdrawals: &BTreeMap<u64, Vec<abi::Withdrawal>>,
    head_slot_hash: B256,
) -> Result<BTreeMap<u64, Vec<abi::Withdrawal>>> {
    if head < tail && head_slot_hash.is_zero() {
        eyre::bail!("pending withdrawal head slot {head} is zero for queue range {head}..{tail}");
    }

    let mut result: BTreeMap<u64, Vec<abi::Withdrawal>> = BTreeMap::new();

    for portal_slot in head..tail {
        let Some(event) = events.get(&portal_slot) else {
            eyre::bail!("no BatchSubmitted event found for pending portal slot {portal_slot}");
        };

        let Some(withdrawals) = slot_withdrawals.get(&portal_slot) else {
            eyre::bail!("no withdrawal data fetched for pending portal slot {portal_slot}");
        };

        if withdrawals.is_empty()
            || abi::Withdrawal::queue_hash(withdrawals) != event.withdrawalQueueHash
        {
            eyre::bail!("withdrawal hash mismatch or empty for portal slot {portal_slot}");
        }

        if portal_slot == head {
            match find_processed_offset(withdrawals, head_slot_hash) {
                Some(offset) => {
                    let remaining = withdrawals[offset..].to_vec();
                    if !remaining.is_empty() {
                        result.insert(portal_slot, remaining);
                    }
                }
                None => {
                    eyre::bail!("cannot determine processed offset for head slot {portal_slot}");
                }
            }
        } else {
            result.insert(portal_slot, withdrawals.clone());
        }
    }

    Ok(result)
}

/// Find the offset into `withdrawals` where the remaining hash chain matches
/// `current_slot_hash`. Returns `Some(0)` if no withdrawals have been processed,
/// `Some(n)` if n have been processed, or `None` if no match is found.
pub(crate) fn find_processed_offset(
    withdrawals: &[abi::Withdrawal],
    current_slot_hash: B256,
) -> Option<usize> {
    if current_slot_hash.is_zero() {
        return Some(withdrawals.len());
    }

    let mut hash = B256::ZERO;
    for (offset, withdrawal) in withdrawals.iter().enumerate().rev() {
        hash = withdrawal.hash_with_tail(hash);
        if hash == current_slot_hash {
            return Some(offset);
        }
    }
    None
}

fn block_with_receipts<P: SphereSequencerProvider>(
    provider: &P,
    number: u64,
) -> Result<(Block, Vec<Receipt>)> {
    let block = provider
        .block_by_number(number)?
        .ok_or_else(|| eyre::eyre!("canonical sphere block {number} not found"))?;
    let receipts = provider
        .receipts_by_block(BlockHashOrNumber::Number(number))?
        .ok_or_else(|| eyre::eyre!("receipts for canonical sphere block {number} not found"))?;
    if block.body.transactions.len() != receipts.len() {
        return Err(eyre::eyre!(
            "sphere block {number} has {} transactions but {} receipts",
            block.body.transactions.len(),
            receipts.len()
        ));
    }
    Ok((block, receipts))
}

/// Read the settlement commitments emitted by the deterministic system transaction in a sphere
/// block.
pub(crate) fn read_sphere_block_snapshot<P: SphereSequencerProvider>(
    provider: &P,
    inbox_address: Address,
    number: u64,
) -> Result<SphereBlockSnapshot> {
    let (_, receipts) = block_with_receipts(provider, number)?;
    let block_hash = provider
        .block_hash(number)?
        .ok_or_else(|| eyre::eyre!("canonical sphere block {number} is missing its hash"))?;
    let mut arc_block_number = None;
    let mut processed_deposit_hash = None;
    let mut processed_deposit_number = None;
    let mut processed_token_count = None;

    for receipt in receipts {
        for log in receipt.logs() {
            if log.address != inbox_address {
                continue;
            }
            let Some(topic) = log.topics().first() else {
                continue;
            };
            let (block_number, deposit_hash, deposit_number, token_count) = match *topic {
                ArcAdvanced::SIGNATURE_HASH => {
                    let event = ArcAdvanced::decode_log(log).map_err(|err| {
                        eyre::eyre!("invalid ArcAdvanced log in block {number}: {err}")
                    })?;
                    (
                        event.arcBlockNumber,
                        event.newProcessedDepositQueueHash,
                        event.lastProcessedDepositNumber,
                        event.lastProcessedEnabledTokenCount,
                    )
                }
                LegacyArcAdvanced::SIGNATURE_HASH => {
                    let event = LegacyArcAdvanced::decode_log(log).map_err(|err| {
                        eyre::eyre!("invalid legacy ArcAdvanced log in block {number}: {err}")
                    })?;
                    (
                        event.arcBlockNumber,
                        event.newProcessedDepositQueueHash,
                        event.lastProcessedDepositNumber,
                        0,
                    )
                }
                _ => {
                    continue;
                }
            };
            if arc_block_number.replace(block_number).is_some() {
                return Err(eyre::eyre!(
                    "sphere block {number} contains more than one ArcAdvanced event"
                ));
            }
            processed_deposit_hash = Some(deposit_hash);
            processed_deposit_number = Some(deposit_number);
            processed_token_count = Some(token_count);
        }
    }

    Ok(SphereBlockSnapshot {
        arc_block_number: arc_block_number
            .ok_or_else(|| eyre::eyre!("sphere block {number} is missing ArcAdvanced"))?,
        processed_deposit_hash: processed_deposit_hash.ok_or_else(|| {
            eyre::eyre!("sphere block {number} is missing its deposit commitment")
        })?,
        processed_deposit_number: processed_deposit_number
            .ok_or_else(|| eyre::eyre!("sphere block {number} is missing its deposit number"))?,
        processed_token_count: processed_token_count
            .ok_or_else(|| eyre::eyre!("sphere block {number} is missing its token cursor"))?,
        block_hash,
    })
}

/// Fetch all sphere block numbers in `[from, to]` that finalized a withdrawal batch.
///
/// This includes zero-withdrawal batches because they still advance the L2
/// withdrawal batch index and therefore require a matching L1 `submitBatch`.
pub(crate) async fn fetch_finalized_batch_boundaries<P: SphereSequencerProvider>(
    provider: &P,
    outbox_address: Address,
    from: u64,
    to: u64,
) -> Result<Vec<FinalizedBatchLog>> {
    if from > to {
        return Ok(Vec::new());
    }

    let boundaries = fetch_finalized_batch_logs(provider, outbox_address, from, to)?;
    if let Some(duplicate) = boundaries
        .windows(2)
        .find(|pair| pair[0].block_number == pair[1].block_number)
    {
        return Err(eyre::eyre!(
            "sphere block {} contains more than one BatchFinalized event",
            duplicate[0].block_number
        ));
    }
    Ok(boundaries)
}

/// Fetch one finalized L2 withdrawal batch.
///
/// The submitted hash and index come from the supplied `BatchFinalized` event.
/// Withdrawal structs are reconstructed from `WithdrawalRequested` logs in the
/// same block: every non-empty withdrawal batch is finalized in the block that
/// contains its requests.
pub(crate) async fn fetch_finalized_batch<P: SphereSequencerProvider>(
    sphere_provider: &P,
    outbox_address: Address,
    target: &FinalizedBatchLog,
) -> Result<FinalizedBatch> {
    let (block, receipts) = block_with_receipts(sphere_provider, target.block_number)?;
    let mut requests = Vec::new();
    for (tx, receipt) in block.body.transactions.iter().zip(&receipts) {
        for log in receipt.logs() {
            if log.address != outbox_address
                || log.topics().first() != Some(&ISphereOutbox::WithdrawalRequested::SIGNATURE_HASH)
            {
                continue;
            }
            let event = ISphereOutbox::WithdrawalRequested::decode_log(log)
                .map_err(|err| {
                    eyre::eyre!(
                        "invalid WithdrawalRequested log in sphere block {}: {err}",
                        target.block_number
                    )
                })?
                .data;
            requests.push((*tx.tx_hash(), event));
        }
    }

    let finalize_tx = block
        .body
        .transactions
        .iter()
        .find(|tx| *tx.tx_hash() == target.tx_hash)
        .ok_or_else(|| {
            eyre::eyre!(
                "missing finalizeWithdrawalBatch tx {} for sphere block {}",
                target.tx_hash,
                target.block_number
            )
        })?;
    let encrypted_senders =
        abi::ISphereOutbox::finalizeWithdrawalBatchCall::abi_decode(finalize_tx.input().as_ref())
            .map_err(|err| {
                eyre::eyre!(
                    "failed to decode finalizeWithdrawalBatch calldata for {}: {err}",
                    target.tx_hash
                )
            })?
            .encryptedSenders;

    if encrypted_senders.len() != requests.len() {
        return Err(eyre::eyre!(
            "encrypted sender count mismatch for batch ending at sphere block {}: {} encrypted senders for {} requests",
            target.block_number,
            encrypted_senders.len(),
            requests.len()
        ));
    }

    let withdrawals = requests
        .into_iter()
        .zip(encrypted_senders)
        .map(|((tx_hash, event), encrypted_sender)| {
            abi::Withdrawal::from_requested_event(&event, tx_hash, encrypted_sender)
        })
        .collect::<Vec<_>>();

    let recomputed_hash = abi::Withdrawal::queue_hash(&withdrawals);
    if recomputed_hash != target.withdrawal_queue_hash {
        return Err(eyre::eyre!(
            "withdrawal hash mismatch for batch ending at sphere block {}: event hash {}, reconstructed hash {}",
            target.block_number,
            target.withdrawal_queue_hash,
            recomputed_hash
        ));
    }

    Ok(FinalizedBatch {
        finalized_hash: target.withdrawal_queue_hash,
        finalized_index: target.withdrawal_batch_index,
        withdrawals,
    })
}

/// Fetch `WithdrawalRequested` events for one portal queue slot.
///
/// A portal queue slot is created only for a non-empty withdrawal batch. The
/// outbox finalizes pending withdrawals in the same sphere block as their
/// requests, so recovery needs to inspect only the block referenced by the
/// slot's `BatchSubmitted.nextBlockHash`.
pub(crate) async fn fetch_slot_withdrawals(
    sphere_provider: &impl SphereSequencerProvider,
    outbox_address: Address,
    block_number: u64,
) -> Result<Vec<abi::Withdrawal>> {
    let boundaries = fetch_finalized_batch_boundaries(
        sphere_provider,
        outbox_address,
        block_number,
        block_number,
    )
    .await?;
    let target = boundaries.into_iter().next().ok_or_else(|| {
        eyre::eyre!("sphere block {block_number} does not contain a BatchFinalized boundary")
    })?;
    Ok(
        fetch_finalized_batch(sphere_provider, outbox_address, &target)
            .await?
            .withdrawals,
    )
}

fn fetch_finalized_batch_logs<P: SphereSequencerProvider>(
    provider: &P,
    outbox_address: Address,
    from: u64,
    to: u64,
) -> Result<Vec<FinalizedBatchLog>> {
    let mut finalized_batches = Vec::new();
    for block_number in from..=to {
        let (block, receipts) = block_with_receipts(provider, block_number)?;
        for (tx_index, (tx, receipt)) in block
            .body
            .transactions
            .iter()
            .zip(receipts.iter())
            .enumerate()
        {
            for (log_index, log) in receipt.logs().iter().enumerate() {
                if log.address != outbox_address
                    || log.topics().first() != Some(&ISphereOutbox::BatchFinalized::SIGNATURE_HASH)
                {
                    continue;
                }
                let event = ISphereOutbox::BatchFinalized::decode_log(log).map_err(|err| {
                    eyre::eyre!("invalid BatchFinalized log in sphere block {block_number}: {err}")
                })?;
                finalized_batches.push(FinalizedBatchLog {
                    block_number,
                    tx_index: tx_index as u64,
                    log_index: log_index as u64,
                    tx_hash: *tx.tx_hash(),
                    withdrawal_queue_hash: event.withdrawalQueueHash,
                    withdrawal_batch_index: event.withdrawalBatchIndex,
                });
            }
        }
    }
    finalized_batches.sort_by_key(|batch| (batch.block_number, batch.tx_index, batch.log_index));
    Ok(finalized_batches)
}

fn backward_log_query_start(hi: u64, floor: u64) -> u64 {
    hi.saturating_sub(LOG_QUERY_BLOCK_CHUNK - 1).max(floor)
}
