mod config;
pub mod protocol;
pub use protocol::SphereProtocolEvmConfig;
pub use config::{SphereEvmConfig, SphereEvmFactory};
pub mod precompiles;
pub mod sphere_evm;

pub use arc_evm::{ArcEvm, ArcEvmConfig, ArcEvmFactory};

use alloy_primitives::{Address, B256};
use sphere_chainspec::SphereChainSpec;
use sphere_precompiles::L1StorageReader;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

/// Creates the EVM config from the node's canonical, composed chain specification.
pub fn create_evm_config(chain_spec: Arc<SphereChainSpec>) -> SphereEvmConfig {
    let arc_chain_spec = chain_spec.inner.clone();
    SphereEvmConfig::new(reth_ethereum::evm::EthEvmConfig::new_with_evm_factory(
        arc_chain_spec.clone(),
        SphereEvmFactory(ArcEvmFactory::new(arc_chain_spec)),
    ))
}

/// An [`L1StorageReader`] wrapper that records successful Arc storage reads.
#[derive(Clone, Debug)]
pub struct RecordingL1StorageReader<L1> {
    inner: L1,
    reads: Arc<Mutex<HashSet<ArcStorageRead>>>,
}

impl<L1> RecordingL1StorageReader<L1> {
    pub fn new(inner: L1) -> Self {
        Self {
            inner,
            reads: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Takes and returns the deduplicated storage reads recorded so far.
    pub fn take_reads(&self) -> HashSet<ArcStorageRead> {
        std::mem::take(&mut self.reads.lock().expect("L1 read recorder lock poisoned"))
    }
}

impl<L1: L1StorageReader> L1StorageReader for RecordingL1StorageReader<L1> {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, sphere_precompiles::L1StateError> {
        let value = self.inner.read_l1_storage(account, slot, block_number)?;
        self.reads
            .lock()
            .expect("L1 read recorder lock poisoned")
            .insert(ArcStorageRead { account, slot });
        Ok(value)
    }
}

/// An Arc L1 storage slot accessed while replaying a Sphere block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArcStorageRead {
    /// Arc account whose storage was accessed.
    pub account: Address,
    /// Storage slot that was accessed.
    pub slot: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_execution_config::chainspec::LOCAL_DEV;
    use reth_ethereum::{chainspec::EthChainSpec, evm::primitives::ConfigureEvm};
    use sphere_precompiles::test_utils::MockL1Reader;
    use sphere_primitives::constants::sphere_chain_id;

    #[test]
    fn evm_env_uses_sphere_chain_id() {
        let mut genesis = LOCAL_DEV.inner.genesis.clone();
        genesis.config.chain_id = sphere_chain_id(1_337, 1).unwrap();
        let sphere = Arc::new(SphereChainSpec::from_genesis_with_l1(genesis, &LOCAL_DEV).unwrap());
        let config = create_evm_config(sphere.clone());
        let env = config.evm_env(sphere.genesis_header()).unwrap();
        assert_eq!(env.cfg_env.chain_id, sphere.chain_id());
    }

    #[test]
    fn l1_storage_recorder_deduplicates_successful_reads() {
        let account = Address::repeat_byte(0xaa);
        let slot = B256::repeat_byte(0xbb);
        let value = B256::repeat_byte(0xcc);
        let reader = RecordingL1StorageReader::new(MockL1Reader::returning(value));

        assert_eq!(reader.read_l1_storage(account, slot, 10).unwrap(), value);
        assert_eq!(reader.read_l1_storage(account, slot, 10).unwrap(), value);
        assert_eq!(
            reader.take_reads(),
            HashSet::from_iter([ArcStorageRead { account, slot }])
        );

        let failing = RecordingL1StorageReader::new(MockL1Reader::failing_storage());
        assert!(failing.read_l1_storage(account, slot, 10).is_err());
        assert!(failing.take_reads().is_empty());
    }
}
