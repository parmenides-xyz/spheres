use alloy_primitives::{Address, B256};
use sphere_precompiles::{L1State, L1StateError, L1StorageReader};
use std::{fmt, sync::Arc};
type ReadSlot = dyn Fn(Address, B256, u64) -> Result<B256, L1StateError> + Send + Sync;
#[derive(Clone)]
pub struct Reader(Arc<ReadSlot>);
impl Reader {
    pub fn new<P: L1StorageReader>(reader: P) -> Self {
        Self(Arc::new(move |account, slot, block_number| {
            reader.read_l1_storage(account, slot, block_number)
        }))
    }
}
impl fmt::Debug for Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader").finish_non_exhaustive()
    }
}
impl L1StorageReader for Reader {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        (self.0)(account, slot, block_number)
    }
}
pub type State = L1State<Reader>;
pub(super) struct Reset(pub(super) Option<State>);
impl Drop for Reset {
    fn drop(&mut self) {
        if let Some(l1) = &self.0 {
            l1.reset_transaction_state()
        }
    }
}
