//! Public witness and commitment types for the Sphere SPF.

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256};

pub use sphere_contracts::{
    BlockTransition, ChaumPedersenProof, DecryptionData, DepositQueueTransition, DepositType,
    EnabledToken, QueuedDeposit, TokenEnablementTransition,
};
/// Public values that the verifier binds to a submitted batch proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct PublicInputs {
    /// Parent Arc chain ID used to domain-separate the Sphere EVM chain ID.
    pub parent_chain_id: u64,
    /// Sphere identifier from which the SPF derives the EVM chain ID.
    pub sphere_id: u32,
    /// Arc block number committed by the submitted batch.
    pub arc_block_number: u64,
    /// Arc block number used to anchor this batch.
    pub anchor_block_number: u64,
    /// Block hash for `anchor_block_number`.
    pub anchor_block_hash: B256,
    /// Withdrawal batch index expected by the portal.
    pub expected_withdrawal_batch_index: u64,
}

/// Complete prover input for one Sphere batch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct BatchWitness {
    /// Values committed by the verifier.
    pub public_inputs: PublicInputs,
    /// Canonical Arc header of the first Sphere block's parent. Its hash and
    /// state root anchor the batch and its execution fields seed replay.
    #[cfg_attr(feature = "serde", serde(with = "sphere_primitives::serde_rlp"))]
    pub parent_header: Header,
    /// Sphere blocks in execution order.
    pub sphere_blocks: Vec<SphereBlock>,
    /// Stateless witness for the Sphere state at the start of the batch.
    pub sphere_state_witness: SphereStateWitness,
    /// Stateless witness for Arc state reads performed during the batch.
    pub arc_state_witness: ArcStateWitness,
    /// RLP-encoded headers ordered from `arc_block_number + 1` through the
    /// anchor block when ancestry verification is needed.
    pub arc_ancestry_headers: Vec<Bytes>,
}

/// Typed inputs for the opening SphereInbox system transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub enum ArcImport {
    Full {
        header_rlp: Bytes,
        deposits: Vec<QueuedDeposit>,
        decryptions: Vec<DecryptionData>,
        enabled_tokens: Vec<EnabledToken>,
    },
    CheckpointOnly {
        headers_rlp: Vec<Bytes>,
    },
}

impl ArcImport {
    pub fn headers_rlp(&self) -> &[Bytes] {
        match self {
            Self::Full { header_rlp, .. } => core::slice::from_ref(header_rlp),
            Self::CheckpointOnly { headers_rlp } => headers_rlp,
        }
    }

    pub fn deposits(&self) -> &[QueuedDeposit] {
        match self {
            Self::Full { deposits, .. } => deposits,
            Self::CheckpointOnly { .. } => &[],
        }
    }
}

/// Sphere block input, including its system-call inputs and raw user transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct SphereBlock {
    pub number: u64,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub beneficiary: Address,
    pub arc_import: ArcImport,
    /// Withdrawal count passed to finalization in this block, if any.
    pub finalize_withdrawal_batch_count: Option<U256>,
    /// Encrypted sender payloads passed to withdrawal finalization.
    pub finalize_withdrawal_batch_encrypted_senders: Vec<Bytes>,
    /// Raw signed user transactions in execution order.
    pub transactions: Vec<Bytes>,
}

/// Stateless Sphere state input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct SphereStateWitness {
    /// Deduplicated RLP-encoded nodes used for Sphere state reads.
    pub node_pool: Vec<Bytes>,
    /// Deduplicated bytecode preimages, indexed by `keccak256(bytecode)`.
    pub bytecodes: Vec<Bytes>,
}

/// Stateless Arc state input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct ArcStateWitness {
    /// RLP-encoded header for the Arc checkpoint bound in the initial Sphere
    /// state. Its decoded state root anchors initial Arc reads.
    pub initial_arc_header_rlp: Bytes,
    /// Deduplicated RLP-encoded MPT nodes used for Arc state reads.
    pub node_pool: Vec<Bytes>,
}

/// Commitments returned by a successful Sphere batch transition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct BatchOutput {
    /// Number of the final executed Sphere header committed by `block_transition.nextBlockHash`.
    pub next_sphere_height: u64,
    /// Hash transition covering every Sphere block in the batch.
    pub block_transition: BlockTransition,
    /// Progress of the SphereInbox deposit queue during the batch.
    pub deposit_queue_transition: DepositQueueTransition,
    /// Progress of the append-only portal token-enablement prefix during the batch.
    pub token_enablement_transition: TokenEnablementTransition,
    /// Hash chain created by finalizing the batch's withdrawals.
    pub withdrawal_queue_hash: B256,
    /// Batch index committed by `SphereOutbox.lastBatch`.
    pub last_batch_commitment: LastBatchCommitment,
}

/// The portion of `SphereOutbox.lastBatch` independently committed by the SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct LastBatchCommitment {
    pub withdrawal_batch_index: u64,
}
