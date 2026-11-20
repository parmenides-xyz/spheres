use alloc::{string::String, sync::Arc};
use spin::Mutex;

use alloy_primitives::{Address, B256};
use thiserror::Error;

/// Raw L1 storage access needed by the anchored Sphere database and L1-backed precompiles.
pub trait L1StorageReader: Clone + Send + Sync + 'static {
    /// Reads `account[slot]` at `block_number` on Arc L1 without gas accounting.
    ///
    /// **IMPORTANT:** Implementations are raw provider hooks. Callers are responsible for dealing
    /// with the execution anchor and charging the appropriate execution gas costs.
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> core::result::Result<B256, L1StateError>;
}

/// Execution-local access to Arc L1 storage at a single finalized block number.
///
/// The **anchor** is the Arc L1 block number against which every external storage read in the
/// current transaction attempt must be resolved. It corresponds to the checkpoint maintained in
/// Sphere state by the native `ArcState` precompile. The anchor starts unset and is selected in one
/// of two ways:
///
/// - For an ordinary transaction, the first L1 read selects the `arcBlockNumber` loaded from the
///   chosen Sphere state.
/// - During `advanceArc`, the native `ArcState` precompile governs advancement: it first
///   validates that the submitted header is the direct child of the stored checkpoint, then
///   advances the anchor to that child before any reads at the new checkpoint.
///
/// Once selected, the anchor is immutable for the transaction attempt. Reads at another block,
/// advancement after a parent-anchor read, and duplicate or non-contiguous advancement are
/// rejected. The Sphere EVM resets the anchor after every transaction attempt, including failed and
/// noncommitting simulations.
///
/// Clones share the selected anchor and provider handle so the Sphere database adapter, `ArcState`,
/// and other native precompiles enforce one view of L1 state. A new `L1State` must be created for
/// each EVM execution context; it must not be shared across independent EVMs.
#[derive(Clone)]
pub struct L1State<P> {
    /// Arc block number selected for the current transaction attempt.
    anchor: Arc<Mutex<Option<u64>>>,
    /// Underlying cache/RPC-backed reader for storage at an explicit Arc block number.
    provider: P,
    /// SpherePortal read through the L1 provider by explicit storage operations.
    portal_address: Address,
}

impl<P> L1State<P> {
    /// Creates execution-local L1 state backed by `provider` for `portal_address`.
    pub fn new(provider: P, portal_address: Address) -> Self {
        Self {
            anchor: Arc::new(Mutex::new(None)),
            provider,
            portal_address,
        }
    }

    /// Clears the selected anchor after the current transaction attempt completes.
    pub fn reset_transaction_state(&self) {
        *self.anchor.lock() = None;
    }

    /// Returns the anchor selected for the current transaction, if any.
    pub fn get_anchor(&self) -> Option<u64> {
        *self.anchor.lock()
    }

    /// Returns the configured SpherePortal address.
    pub const fn portal(&self) -> Address {
        self.portal_address
    }

    fn set_anchor(&self, new: u64) -> Result<(), L1StateError> {
        let mut anchor = self.anchor.lock();
        match *anchor {
            None => {
                *anchor = Some(new);
                Ok(())
            }
            Some(current) if current == new => Ok(()),
            Some(current) => Err(L1StateError::AnchorConflict { current, new }),
        }
    }

    /// Selects the final anchor after `ArcState.finalizeArc` validates a contiguous range.
    ///
    /// Advancement is valid only before any L1 read has selected an anchor and only from a parent
    /// to a later checkpoint.
    pub fn advance_anchor(&self, from: u64, to: u64) -> Result<(), L1StateError> {
        let mut anchor = self.anchor.lock();
        if to <= from {
            return Err(L1StateError::AdvanceArcConflict { from, to });
        } else if let Some(current) = *anchor {
            return Err(L1StateError::AnchorConflict { current, new: to });
        }

        *anchor = Some(to);
        Ok(())
    }
}

impl<P: L1StorageReader> L1State<P> {
    /// Reads L1 storage through the provider without gas metering, after selecting or validating
    /// `block_number` as this transaction's anchor.
    ///
    pub fn read_l1_storage_unmetered(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.set_anchor(block_number)?;
        self.provider.read_l1_storage(account, slot, block_number)
    }
}

/// Failure to read or advance execution-local Arc L1 state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum L1StateError {
    /// The underlying L1 provider could not resolve storage at the requested block.
    #[error(
        "Arc L1 storage unavailable account={account} slot={slot} block={block_number}: {reason}"
    )]
    StorageUnavailable {
        /// Arc account whose storage was requested.
        account: Address,
        /// Requested storage slot.
        slot: B256,
        /// Arc block number at which storage was requested.
        block_number: u64,
        /// Provider failure diagnostic.
        reason: String,
    },
    /// An L1 read disagreed with the anchor already selected for this transaction.
    #[error("Arc L1 read at anchor {new} conflicts with currently selected anchor {current}")]
    AnchorConflict {
        /// Anchor already selected for this transaction.
        current: u64,
        /// Anchor requested by the new read.
        new: u64,
    },
    /// Arc advancement was non-contiguous or happened after an anchor was selected.
    #[error("cannot advance Arc L1 anchor from {from} to {to}")]
    AdvanceArcConflict {
        /// Parent Arc block number.
        from: u64,
        /// Requested child Arc block number.
        to: u64,
    },
}

impl L1StateError {
    /// Returns whether this is an underlying storage-provider failure.
    pub const fn is_storage_unavailable(&self) -> bool {
        matches!(self, Self::StorageUnavailable { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockL1Reader;

    fn read(l1: &L1State<MockL1Reader>, anchor: u64) -> Result<B256, L1StateError> {
        l1.read_l1_storage_unmetered(Address::ZERO, B256::ZERO, anchor)
    }

    #[test]
    fn l1_state_rejects_advance_after_parent_read() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        read(&l1, 10).unwrap();
        assert!(l1.advance_anchor(10, 11).is_err());
    }

    #[test]
    fn l1_state_accepts_reads_at_advanced_anchor() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 11).unwrap();
        read(&l1, 11).unwrap();
        assert_eq!(l1.get_anchor(), Some(11));
    }

    #[test]
    fn l1_state_clones_reject_reads_at_different_anchors() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        let clone = l1.clone();
        read(&l1, 10).unwrap();
        assert!(read(&clone, 11).is_err());
    }

    #[test]
    fn l1_state_rejects_duplicate_advance() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 11).unwrap();
        assert!(l1.advance_anchor(11, 12).is_err());
    }

    #[test]
    fn l1_state_accepts_forward_range_and_rejects_non_forward_advance() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 12).unwrap();
        assert_eq!(l1.get_anchor(), Some(12));

        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        assert!(l1.advance_anchor(10, 10).is_err());
        assert!(l1.advance_anchor(10, 9).is_err());
        assert_eq!(l1.get_anchor(), None);
    }

    #[test]
    fn l1_state_reset_allows_a_new_anchor() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        read(&l1, 10).unwrap();
        l1.reset_transaction_state();
        l1.advance_anchor(10, 11).unwrap();
        assert_eq!(l1.get_anchor(), Some(11));
    }
}
