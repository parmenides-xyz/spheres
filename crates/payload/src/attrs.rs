//! Sphere payload types.

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload};
use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadId};
use alloy_rpc_types_eth::Withdrawal;
use arc_execution_config::gas_fee::encode_base_fee_to_bytes;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_payload_primitives::{BuiltPayload, PayloadAttributes, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, SealedBlock, SealedHeader};
use serde::{Deserialize, Serialize};
use sphere_l1::PreparedL1Block;

/// Explicit opening Arc system-call variant for a Sphere payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArcImport {
    Full(Box<PreparedL1Block>),
    CheckpointOnly(Vec<SealedHeader<Header>>),
}

impl ArcImport {
    pub(crate) fn is_checkpoint_only(&self) -> bool {
        matches!(self, Self::CheckpointOnly(_))
    }

    pub(crate) fn follows_checkpoint_blocks(&self) -> bool {
        match self {
            Self::Full(prepared) => prepared.follows_checkpoint_blocks,
            Self::CheckpointOnly(_) => false,
        }
    }

    pub(crate) fn total_deposits(&self) -> usize {
        match self {
            Self::Full(prepared) => prepared.queued_deposits.len(),
            Self::CheckpointOnly(_) => 0,
        }
    }

    pub(crate) fn enabled_tokens(&self) -> usize {
        match self {
            Self::Full(prepared) => prepared.enabled_tokens.len(),
            Self::CheckpointOnly(_) => 0,
        }
    }
}

/// Sphere RPC payload attributes — the type that flows through FCU.
///
/// Carries standard Ethereum attributes and
/// the prepared L1 block whose deposits should be included in this sphere block.
/// The L1 data is set by the SphereEngine before sending
/// FCU and is skipped during (de)serialisation since it only travels through
/// in-process channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpherePayloadAttributes {
    /// Standard Ethereum payload attributes.
    pub inner: EthPayloadAttributes,

    /// Prepared L1 block to process in this sphere block. Every sphere block
    /// processes exactly one L1 block via `advanceArc`. Decryption and ABI
    /// encoding have already been performed by the engine.
    pub arc_import: ArcImport,
}

impl PayloadAttributes for SpherePayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        reth_payload_primitives::payload_id(parent_hash, &self.inner)
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number
    }
}

impl SpherePayloadAttributes {
    /// Returns a reference to the prepared L1 block data.
    pub fn arc_import(&self) -> &ArcImport {
        &self.arc_import
    }

    /// Returns the extra data for the block header.
    pub fn extra_data(&self) -> Bytes {
        encode_base_fee_to_bytes(0)
    }

    pub fn suggested_fee_recipient(&self) -> Address {
        self.inner.suggested_fee_recipient
    }

    pub fn prev_randao(&self) -> B256 {
        self.inner.prev_randao
    }
}

/// Sphere payload types.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SpherePayloadTypes;

impl PayloadTypes for SpherePayloadTypes {
    type BuiltPayload = EthBuiltPayload<sphere_primitives::SpherePrimitives>;
    type PayloadAttributes = SpherePayloadAttributes;
    type ExecutionData = ExecutionData;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        ExecutionData { payload, sidecar }
    }
}
