//! Execution-local database adapter that overlays finalized Arc L1 reads while preserving
//! the caller-provided Sphere database as the sole canonical state backend.

use std::fmt;

use super::reader::State;
use alloy_evm::Database;
use alloy_primitives::{Address, B256, U256};
use arc_precompiles::native_coin_control::NATIVE_COIN_CONTROL_ADDRESS;
use revm::{
    context::{
        DBErrorMarker,
        result::{AnyError, EVMError},
    },
    database_interface::Database as RevmDatabase,
    primitives::{AddressMap, StorageKey, StorageValue},
    state::{Account, AccountInfo, Bytecode},
};
use sphere_contracts::TRANSFERS_ENABLED_SLOT;
use sphere_precompiles::L1StateError;
use sphere_precompiles::arc_state::slots::ARC_BLOCK_NUMBER;
use sphere_primitives::constants::ARC_STATE_ADDRESS;
use thiserror::Error;

/// Resolves mirrored L1 reads at the active Arc anchor and forwards all other database
/// operations to the caller-provided Sphere database.
pub struct L1OverlayDB<DB> {
    inner: DB,
    l1: Option<State>,
    denylist: Option<Address>,
}

impl<DB> L1OverlayDB<DB> {
    /// Creates an adapter around the caller-provided database.
    pub fn new(inner: DB, l1: Option<State>, denylist: Option<Address>) -> Self {
        Self {
            inner,
            l1,
            denylist,
        }
    }

    /// Returns the original caller-provided database.
    pub const fn inner(&self) -> &DB {
        &self.inner
    }

    /// Returns the original caller-provided database mutably.
    pub const fn inner_mut(&mut self) -> &mut DB {
        &mut self.inner
    }

    /// Recovers the original caller-provided database.
    pub fn into_inner(self) -> DB {
        self.inner
    }
}

impl<DB: fmt::Debug> fmt::Debug for L1OverlayDB<DB> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L1OverlayDB")
            .field("inner", &self.inner)
            .field("portal", &self.l1.as_ref().map(State::portal))
            .finish_non_exhaustive()
    }
}

impl<DB: Database> L1OverlayDB<DB> {
    fn anchor(&mut self) -> Result<u64, SphereDbError<DB::Error>> {
        if let Some(anchor) = self.l1.as_ref().and_then(State::get_anchor) {
            return Ok(anchor);
        }

        let value = self
            .inner
            .storage(ARC_STATE_ADDRESS, ARC_BLOCK_NUMBER)
            .map_err(SphereDbError::Inner)?;
        let anchor = u64::try_from(value).map_err(|_| SphereDbError::AnchorOverflow(value))?;
        Ok(anchor)
    }

    /// Rejects writes to Arc's policy accounts before committing Sphere state.
    pub fn sanitize_state(
        &self,
        state: &mut AddressMap<Account>,
    ) -> Result<(), SphereDbError<DB::Error>> {
        for address in [Some(NATIVE_COIN_CONTROL_ADDRESS), self.denylist]
            .into_iter()
            .flatten()
        {
            if let Some(account) = state.get(&address) {
                if account.info != *account.original_info {
                    return Err(SphereDbError::L1Write {
                        address,
                        slot: U256::ZERO,
                    });
                }
                if let Some((&slot, _)) = account.changed_storage_slots().next() {
                    return Err(SphereDbError::L1Write { address, slot });
                }
                state.remove(&address);
            }
        }
        if let Some(portal) = self.l1.as_ref().map(State::portal)
            && let Some(account) = state.get_mut(&portal)
            && let Some(slot) = account.storage.remove(&TRANSFERS_ENABLED_SLOT)
            && slot.is_changed()
        {
            return Err(SphereDbError::L1Write {
                address: portal,
                slot: TRANSFERS_ENABLED_SLOT,
            });
        }
        Ok(())
    }
}

impl<DB: Database> RevmDatabase for L1OverlayDB<DB> {
    type Error = SphereDbError<DB::Error>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic(address).map_err(SphereDbError::Inner)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner
            .code_by_hash(code_hash)
            .map_err(SphereDbError::Inner)
    }

    fn storage(&mut self, address: Address, slot: StorageKey) -> Result<StorageValue, Self::Error> {
        if address != NATIVE_COIN_CONTROL_ADDRESS
            && self.denylist != Some(address)
            && !(self
                .l1
                .as_ref()
                .is_some_and(|state| state.portal() == address)
                && slot == TRANSFERS_ENABLED_SLOT)
        {
            return self
                .inner
                .storage(address, slot)
                .map_err(SphereDbError::Inner);
        }

        let anchor = self.anchor()?;
        self.l1
            .as_ref()
            .ok_or(SphereDbError::MissingReader)?
            .read_l1_storage_unmetered(address, B256::from(slot), anchor)
            .map(Into::into)
            .map_err(SphereDbError::L1State)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number).map_err(SphereDbError::Inner)
    }
}

/// Database error produced by [`L1OverlayDB`].
#[derive(Debug, Error)]
pub enum SphereDbError<E> {
    #[error("Arc policy reader is unavailable")]
    MissingReader,
    /// Error from the caller-provided database.
    #[error("inner database error: {0}")]
    Inner(#[source] E),
    /// The selected Sphere state contains an invalid Arc anchor.
    #[error("invalid Arc anchor (does not fit in u64): {0}")]
    AnchorOverflow(U256),
    /// Execution-local Arc L1 state could not be read or advanced consistently.
    #[error(transparent)]
    L1State(#[from] L1StateError),
    /// A transaction attempted to persist mirrored Arc-owned state.
    #[error("write to mirrored Arc storage address={address} slot={slot}")]
    L1Write { address: Address, slot: U256 },
}

impl<E: DBErrorMarker> DBErrorMarker for SphereDbError<E> {}

impl<E: DBErrorMarker> SphereDbError<E> {
    pub(crate) fn into_evm_error<TxError>(self) -> EVMError<E, TxError> {
        match self {
            Self::Inner(error) => EVMError::Database(error),
            error => EVMError::CustomAny(AnyError::new(error)),
        }
    }
}
