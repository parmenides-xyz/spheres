//! Extension traits for reading ArcState fields from sphere storage.

use alloy_eips::NumHash;
use alloy_primitives::B256;
use reth_provider::ProviderResult;
use reth_storage_api::StateProvider;

use crate::{abi::ARC_STATE_ADDRESS, precompiles::arc_state::slots};

/// Extension trait for reading ArcState fields from sphere storage.
pub trait ArcStateExt {
    /// Returns the current `arcBlockNumber` (the latest L1 block processed by the sphere).
    fn arc_block_number(&self) -> ProviderResult<u64>;

    /// Returns the current `arcBlockHash` (the hash of the latest L1 block processed).
    fn arc_block_hash(&self) -> ProviderResult<B256>;

    /// Returns the current L1 block as a [`NumHash`] (number + hash).
    fn arc_num_hash(&self) -> ProviderResult<NumHash> {
        Ok(NumHash {
            number: self.arc_block_number()?,
            hash: self.arc_block_hash()?,
        })
    }
}

impl<T: StateProvider + ?Sized> ArcStateExt for T {
    fn arc_block_number(&self) -> ProviderResult<u64> {
        let block_number = self
            .storage(ARC_STATE_ADDRESS, slots::ARC_BLOCK_NUMBER.into())?
            .unwrap_or_default();
        Ok(block_number.to::<u64>())
    }

    fn arc_block_hash(&self) -> ProviderResult<B256> {
        Ok(self
            .storage(ARC_STATE_ADDRESS, slots::ARC_BLOCK_HASH.into())?
            .map(B256::from)
            .unwrap_or_default())
    }
}

/// Extension trait for reading ArcState fields from a [`reth_provider::Chain`]'s execution
/// outcome.
///
/// Separate from [`ArcStateExt`] because `Chain` does not implement [`StateProvider`] — it
/// reads from the bundled [`ExecutionOutcome`](reth_provider::ExecutionOutcome) instead.
pub trait ChainArcStateExt {
    /// Returns the current `arcBlockNumber` from the chain's execution outcome.
    fn arc_block_number(&self) -> u64;

    /// Returns the current `arcBlockHash` from the chain's execution outcome.
    fn arc_block_hash(&self) -> B256;

    /// Returns the current L1 block as a [`NumHash`] (number + hash).
    fn arc_num_hash(&self) -> NumHash {
        NumHash {
            number: self.arc_block_number(),
            hash: self.arc_block_hash(),
        }
    }
}

impl<N: reth_primitives_traits::NodePrimitives> ChainArcStateExt for reth_provider::Chain<N> {
    fn arc_block_number(&self) -> u64 {
        let block_number = self
            .execution_outcome()
            .storage(&ARC_STATE_ADDRESS, slots::ARC_BLOCK_NUMBER)
            .unwrap_or_default();
        block_number.to::<u64>()
    }

    fn arc_block_hash(&self) -> B256 {
        self.execution_outcome()
            .storage(&ARC_STATE_ADDRESS, slots::ARC_BLOCK_HASH)
            .map(B256::from)
            .unwrap_or_default()
    }
}
