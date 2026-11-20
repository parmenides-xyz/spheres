//! Sphere chain specification.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{
    Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
    ForkFilter, ForkId, Hardfork, Hardforks, Head, make_genesis_header,
};
use reth_network_peers::NodeRecord;
use reth_primitives_traits::SealedHeader;
use std::{fmt::Display, sync::Arc};
use arc_execution_config::chainspec::{
    ArcChainSpec, BaseFeeConfig, BaseFeeConfigProvider, BlockGasLimitConfig, BlockGasLimitProvider,
    LOCAL_DEV, bundled_chainspec_for_chain_id,
};
use arc_execution_config::hardforks::{ArcHardfork, ARC_TESTNET_HARDFORKS};
use sphere_primitives::constants::{SphereChainIdError, decode_l1_chain_id, decode_sphere_chain_id};

const ARC_FORK_FIELDS: [(ArcHardfork, &str); 6] = [
    (ArcHardfork::Zero3, "zero3Block"),
    (ArcHardfork::Zero4, "zero4Block"),
    (ArcHardfork::Zero5, "zero5Block"),
    (ArcHardfork::Zero6, "zero6Block"),
    (ArcHardfork::Zero7, "zero7Time"),
    (ArcHardfork::Zero8, "zero8Time"),
];

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Chain specification for a Sphere.
///
/// Spheres use the underlying Arc and Ethereum hardfork schedule, inheriting missing
/// activations when their parent chain is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphereChainSpec {
    /// Underlying Arc chain specification.
    pub inner: Arc<ArcChainSpec>,
}

impl SphereChainSpec {
    /// Converts a genesis configuration into a Sphere chain specification.
    ///
    /// Known public and local development chains inherit their parent schedule. Custom chains
    /// use only the supplied genesis, so dependency updates cannot activate omitted forks.
    pub fn from_genesis(genesis: Genesis) -> Result<Self, SphereChainSpecError> {
        let parent_chain_id = decode_l1_chain_id(genesis.config.chain_id)?;
        if let Some(parent) = arc_chain_spec_for_l1(parent_chain_id) {
            return Self::from_genesis_with_l1(genesis, parent.as_ref());
        }
        Ok(Self::from_explicit_genesis(genesis))
    }

    /// Converts a genesis configuration using an already-resolved L1 chain specification.
    ///
    /// This supports custom L1 chains whose hardfork schedule is not globally registered.
    pub fn from_genesis_with_l1(
        mut genesis: Genesis,
        l1: &ArcChainSpec,
    ) -> Result<Self, SphereChainSpecError> {
        let parent_chain_id = decode_l1_chain_id(genesis.config.chain_id)?;
        if parent_chain_id == arc_execution_config::chain_ids::TESTNET_CHAIN_ID {
            let mut inner = ChainSpec::from_genesis(genesis);
            inner.hardforks = ARC_TESTNET_HARDFORKS.clone();
            inner.genesis_header = SealedHeader::new_unhashed(make_genesis_header(
                &inner.genesis,
                &inner.hardforks,
            ));
            return Ok(Self {
                inner: Arc::new(ArcChainSpec::new(inner)),
            });
        }

        inherit_parent_fork_activations(&mut genesis, l1)?;
        let mut sphere = ArcChainSpec::from(genesis);

        for (fork, key) in ARC_FORK_FIELDS {
            if sphere.genesis().config.extra_fields.contains_key(key) {
                continue;
            }
            let condition = l1.fork(fork);
            if condition != ForkCondition::Never {
                sphere.inner.hardforks.insert(fork, condition);
            }
        }

        Ok(Self {
            inner: Arc::new(sphere),
        })
    }

    /// Sphere identifier encoded in the genesis chain ID.
    pub fn sphere_id(&self) -> u32 {
        decode_sphere_chain_id(self.inner.genesis().config.chain_id)
            .expect("SphereChainSpec validates its chain ID during construction")
            .1
    }

    fn from_explicit_genesis(genesis: Genesis) -> Self {
        let sphere = ArcChainSpec::from(genesis);
        Self {
            inner: Arc::new(sphere),
        }
    }
}

fn inherit_parent_fork_activations(
    sphere_genesis: &mut Genesis,
    l1: &ArcChainSpec,
) -> Result<(), serde_json::Error> {
    let mut sphere_config = serde_json::to_value(&sphere_genesis.config)?;
    let l1_config = serde_json::to_value(reth_chainspec::create_chain_config(
        Some(l1.chain()),
        &l1.inner.hardforks,
        None,
        Default::default(),
    ))?;
    let sphere_fields = sphere_config
        .as_object_mut()
        .expect("ChainConfig must serialize as a JSON object");
    let l1_fields = l1_config
        .as_object()
        .expect("ChainConfig must serialize as a JSON object");

    for (name, value) in l1_fields {
        if name.ends_with("Block") || name.ends_with("Time") {
            sphere_fields
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }

    sphere_genesis.config = serde_json::from_value(sphere_config)?;
    Ok(())
}

impl Hardforks for SphereChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthChainSpec for SphereChainSpec {
    type Header = <ArcChainSpec as EthChainSpec>::Header;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        self.inner.display_hardforks()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.inner.bootnodes()
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, _parent: &Self::Header, _target_timestamp: u64) -> Option<u64> {
        Some(0)
    }
}

impl EthereumHardforks for SphereChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl EthExecutorSpec for SphereChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.inner.deposit_contract_address()
    }
}

impl BlockGasLimitProvider for SphereChainSpec {
    fn block_gas_limit_config(&self, block_height: u64) -> BlockGasLimitConfig {
        self.inner.block_gas_limit_config(block_height)
    }
}

impl BaseFeeConfigProvider for SphereChainSpec {
    fn base_fee_config(&self, block_height: u64) -> BaseFeeConfig {
        self.inner.base_fee_config(block_height)
    }
}

/// Sphere chain specification parser.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Default)]
pub struct SphereChainSpecParser;

#[cfg(feature = "cli")]
impl reth_cli::chainspec::ChainSpecParser for SphereChainSpecParser {
    type ChainSpec = SphereChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &[];

    fn parse(s: &str) -> eyre::Result<std::sync::Arc<Self::ChainSpec>> {
        let genesis = reth_cli::chainspec::parse_genesis(s)?;
        Ok(Arc::new(SphereChainSpec::from_genesis(genesis)?))
    }
}

/// Failure to resolve the canonical chain specification for a sphere.
#[derive(Debug, thiserror::Error)]
pub enum SphereChainSpecError {
    /// The sphere chain ID is not a valid encoding of its parent and sphere IDs.
    #[error(transparent)]
    InvalidChainId(#[from] SphereChainIdError),
    /// The inherited parent fork activations could not be applied to the Sphere genesis.
    #[error("failed to compose Sphere genesis config: {0}")]
    InvalidGenesisConfig(#[from] serde_json::Error),
}

/// Returns the Arc chain specification whose hardfork schedule a parent uses.
///
/// Local development chains 1337 and 31337 use the Arc LOCAL_DEV schedule. Custom chains
/// have no implicit parent schedule.
pub fn arc_chain_spec_for_l1(chain_id: u64) -> Option<Arc<ArcChainSpec>> {
    bundled_chainspec_for_chain_id(chain_id).or_else(|| match chain_id {
        1_337 | 31_337 => Some(LOCAL_DEV.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_execution_config::chainspec::TESTNET;
    use arc_execution_config::hardforks::{ArcHardfork, is_arc_fork_active};
    #[cfg(feature = "cli")]
    use reth_cli::chainspec::ChainSpecParser;
    use sphere_primitives::constants::sphere_chain_id;

    fn dev_sphere_spec(sphere_id: u32) -> SphereChainSpec {
        let mut genesis = LOCAL_DEV.genesis().clone();
        genesis.config.chain_id = sphere_chain_id(LOCAL_DEV.chain_id(), sphere_id).unwrap();
        SphereChainSpec::from_genesis(genesis).unwrap()
    }

    #[test]
    fn delegates_arc_chain_behavior() {
        let sphere = dev_sphere_spec(1);

        assert_eq!(sphere.chain_id(), sphere_chain_id(LOCAL_DEV.chain_id(), 1).unwrap());
        for &hardfork in ArcHardfork::VARIANTS {
            assert_eq!(sphere.fork(hardfork), LOCAL_DEV.fork(hardfork));
        }
    }

    #[test]
    fn hardfork_schedule_matches_arc() {
        let sphere = dev_sphere_spec(4);
        let sphere_forks: Vec<_> = sphere
            .forks_iter()
            .map(|(fork, condition)| (fork.name(), condition))
            .collect();
        let arc_forks: Vec<_> = LOCAL_DEV
            .forks_iter()
            .map(|(fork, condition)| (fork.name(), condition))
            .collect();
        assert_eq!(sphere_forks, arc_forks);
        assert_eq!(sphere.latest_fork_id(), LOCAL_DEV.latest_fork_id());
    }

    #[test]
    fn arc_hardfork_activates_at_boundary() {
        let mut genesis = LOCAL_DEV.genesis().clone();
        genesis.config.chain_id = sphere_chain_id(LOCAL_DEV.chain_id(), 5).unwrap();
        genesis
            .config
            .extra_fields
            .insert_value("zero7Time".to_string(), 100_u64)
            .unwrap();
        let sphere = SphereChainSpec::from_genesis(genesis).unwrap();

        assert!(!is_arc_fork_active(&sphere, ArcHardfork::Zero7, 0, 99));
        assert!(is_arc_fork_active(&sphere, ArcHardfork::Zero7, 0, 100));
    }

    #[test]
    fn genesis_inherits_missing_parent_hardforks_everywhere() {
        let mut genesis = TESTNET.genesis().clone();
        genesis.config.chain_id = sphere_chain_id(TESTNET.chain_id(), 7).unwrap();
        genesis.config.london_block = None;
        genesis.config.shanghai_time = None;
        genesis.config.cancun_time = None;
        genesis.config.prague_time = None;
        let raw = ArcChainSpec::from(genesis.clone());
        let sphere = SphereChainSpec::from_genesis(genesis).unwrap();

        assert_eq!(sphere.chain_id(), raw.chain_id());
        assert_ne!(sphere.genesis_hash(), raw.genesis_hash());
        assert!(raw.genesis_header().base_fee_per_gas.is_none());
        assert!(raw.genesis_header().withdrawals_root.is_none());
        assert!(
            raw.genesis_header()
                .parent_beacon_block_root
                .is_none()
        );
        assert!(raw.genesis_header().requests_hash.is_none());
        assert!(sphere.genesis_header().base_fee_per_gas.is_some());
        assert!(sphere.genesis_header().withdrawals_root.is_some());
        assert!(
            sphere.genesis_header()
                .parent_beacon_block_root
                .is_some()
        );
        assert!(sphere.genesis_header().requests_hash.is_some());
        for &hardfork in EthereumHardfork::VARIANTS {
            assert_eq!(
                sphere.ethereum_fork_activation(hardfork),
                TESTNET.ethereum_fork_activation(hardfork)
            );
        }
        for &hardfork in ArcHardfork::VARIANTS {
            assert_eq!(sphere.fork(hardfork), TESTNET.fork(hardfork));
        }
    }

    #[test]
    fn genesis_accepts_an_already_resolved_custom_l1_spec() {
        const CUSTOM_L1_CHAIN_ID: u64 = 31_318;

        let mut l1_genesis = LOCAL_DEV.genesis().clone();
        l1_genesis.config.chain_id = CUSTOM_L1_CHAIN_ID;
        l1_genesis.config.osaka_time = Some(456);
        let l1 = ArcChainSpec::from(l1_genesis);

        let mut sphere_genesis = LOCAL_DEV.genesis().clone();
        sphere_genesis.config.chain_id = sphere_chain_id(CUSTOM_L1_CHAIN_ID, 8).unwrap();
        sphere_genesis.config.osaka_time = Some(123);
        sphere_genesis
            .config
            .extra_fields
            .insert_value("zero7Time".to_string(), 789_u64)
            .unwrap();
        let sphere = SphereChainSpec::from_genesis_with_l1(sphere_genesis, &l1).unwrap();

        assert_eq!(
            sphere.ethereum_fork_activation(EthereumHardfork::Osaka),
            ForkCondition::Timestamp(123)
        );
        assert_eq!(
            sphere.fork(ArcHardfork::Zero7),
            ForkCondition::Timestamp(789)
        );
    }

    #[test]
    fn next_block_base_fee_is_zero() {
        let sphere = dev_sphere_spec(2);
        let parent = sphere.genesis_header();
        let timestamp = parent.timestamp;

        assert_ne!(LOCAL_DEV.next_block_base_fee(parent, timestamp), Some(0));
        assert_eq!(sphere.next_block_base_fee(parent, timestamp), Some(0));
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_parses_sphere_genesis_json() {
        let mut genesis = LOCAL_DEV.genesis().clone();
        let chain_id = sphere_chain_id(LOCAL_DEV.chain_id(), 9).unwrap();
        genesis.config.chain_id = chain_id;
        let json = serde_json::to_string(&genesis).unwrap();
        let sphere = SphereChainSpecParser::parse(&json).expect("valid Sphere genesis JSON");

        assert_eq!(sphere.chain_id(), chain_id);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_rejects_named_arc_chain() {
        assert!(SphereChainSpecParser::parse("arc-localdev").is_err());
    }

    #[test]
    fn custom_genesis_preserves_historical_schedule() {
        let genesis = historical_custom_genesis();
        let expected = ArcChainSpec::from(genesis.clone());
        let sphere = SphereChainSpec::from_genesis(genesis.clone()).unwrap();

        assert_eq!(sphere.genesis(), &genesis);
        assert_eq!(sphere.genesis_hash(), expected.genesis_hash());
        assert_eq!(sphere.fork(ArcHardfork::Zero6), ForkCondition::Block(0));
        assert_eq!(sphere.fork(ArcHardfork::Zero7), ForkCondition::Never);
        assert_eq!(sphere.fork(ArcHardfork::Zero8), ForkCondition::Never);
        assert_eq!(sphere.sphere_id(), 11);
        assert!(arc_chain_spec_for_l1(31_318).is_none());
    }

    #[test]
    fn custom_genesis_preserves_future_activation() {
        let mut genesis = historical_custom_genesis();
        genesis
            .config
            .extra_fields
            .insert("zero7Time".into(), serde_json::json!(1_000));
        let sphere = SphereChainSpec::from_genesis(genesis).unwrap();

        assert!(!is_arc_fork_active(&sphere, ArcHardfork::Zero7, 0, 999));
        assert!(is_arc_fork_active(&sphere, ArcHardfork::Zero7, 0, 1_000));
        assert!(is_arc_fork_active(&sphere, ArcHardfork::Zero7, 0, u64::MAX));
    }

    #[cfg(feature = "cli")]
    #[test]
    fn parser_preserves_custom_genesis_schedule() {
        let genesis = historical_custom_genesis();
        let sphere = SphereChainSpecParser::parse(&serde_json::to_string(&genesis).unwrap()).unwrap();

        assert_eq!(sphere.genesis(), &genesis);
        assert_eq!(sphere.fork(ArcHardfork::Zero7), ForkCondition::Never);
        assert_eq!(sphere.fork(ArcHardfork::Zero8), ForkCondition::Never);
    }

    #[test]
    fn custom_genesis_still_rejects_invalid_chain_ids() {
        let mut genesis = historical_custom_genesis();
        genesis.config.chain_id = 0;
        assert!(matches!(
            SphereChainSpec::from_genesis(genesis),
            Err(SphereChainSpecError::InvalidChainId(_))
        ));
    }

    fn historical_custom_genesis() -> Genesis {
        let mut genesis = LOCAL_DEV.genesis().clone();
        genesis.config.chain_id = sphere_chain_id(31_318, 11).unwrap();
        genesis
            .config
            .extra_fields
            .insert("zero7Time".into(), serde_json::Value::Null);
        genesis.config.extra_fields.remove("zero8Time");
        genesis
    }
}
