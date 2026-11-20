//! Authenticates Sphere genesis and its Portal creation on Arc.

use std::collections::BTreeSet;

use alloy_consensus::Header;
use alloy_eips::{BlockId, BlockNumHash};
use alloy_network::BlockResponse as _;
use alloy_network::Ethereum;
use alloy_primitives::{Address, B256, U256};
use alloy_provider::{DynProvider, Provider as _};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::SolEvent as _;
use futures::{StreamExt as _, stream};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_evm::ConfigureEvm;
use reth_storage_api::StateProviderFactory;
use sphere_contracts::spheres::SphereFactory;
use sphere_primitives::SpherePrimitives;

use crate::{
    AttemptError, CheckerConfig,
    accounting::State,
    decode_event,
    l1::{classify_rpc_error, validate_rpc_header},
    l2::read_sphere_genesis,
    persistence::{self, Checkpoint},
};

const GENESIS_BLOCK: u64 = 0;
const LOG_QUERY_BLOCKS: u64 = 10_000;
const LOG_QUERY_CONCURRENCY: usize = 8;

/// Authenticated Sphere genesis and Portal identity, without replayed accounting state.
pub(crate) struct Bootstrap {
    identity: persistence::Identity,
    sphere: persistence::BlockRef,
    arc: persistence::BlockRef,
}

impl Bootstrap {
    pub(crate) const fn identity(&self) -> persistence::Identity {
        self.identity
    }

    pub(crate) const fn sphere(&self) -> persistence::BlockRef {
        self.sphere
    }

    /// Build the empty checkpoint preceding Portal creation.
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            identity: self.identity,
            sphere: self.sphere,
            arc: self.arc,
            state: State::default(),
        }
    }
}

/// Discover and authenticate the identity encoded by local Sphere genesis.
pub(crate) async fn discover<P>(
    provider: &P,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
    l1: &DynProvider<Ethereum>,
    config: &CheckerConfig,
) -> Result<Bootstrap, AttemptError>
where
    P: ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: EthChainSpec<Header = Header>,
{
    let context = read_context(provider, evm_config, l1, config).await?;
    let creation = discover_creation(l1, config, context.arc.number).await?;
    finish_bootstrap(context, l1, config, creation, CreationSource::Discovery).await
}

/// Authenticate the creation coordinate retained by an existing database.
pub(crate) async fn authenticate<P>(
    provider: &P,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
    l1: &DynProvider<Ethereum>,
    config: &CheckerConfig,
    identity: persistence::Identity,
) -> Result<Bootstrap, AttemptError>
where
    P: ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: EthChainSpec<Header = Header>,
{
    let context = read_context(provider, evm_config, l1, config).await?;
    if context.identity(config, identity.creation) != identity {
        return Err(AttemptError::disable(eyre::eyre!(
            "checker database identity does not match the configured Sphere"
        )));
    }
    finish_bootstrap(
        context,
        l1,
        config,
        identity.creation,
        CreationSource::Persistence,
    )
    .await
}

/// Local genesis fields authenticated independently from Portal creation.
struct BootstrapContext {
    l1_chain_id: u64,
    sphere: persistence::BlockRef,
    arc: BlockNumHash,
    initial_token: Address,
}

impl BootstrapContext {
    const fn identity(
        &self,
        config: &CheckerConfig,
        creation: persistence::BlockRef,
    ) -> persistence::Identity {
        persistence::Identity {
            l1_chain_id: self.l1_chain_id,
            sphere_chain_id: config.sphere_chain_id,
            sphere_id: config.sphere_id,
            portal: config.portal_address,
            creation,
        }
    }
}

/// Authenticate configured chain identity and read local Sphere genesis.
async fn read_context<P>(
    provider: &P,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
    l1: &DynProvider<Ethereum>,
    config: &CheckerConfig,
) -> Result<BootstrapContext, AttemptError>
where
    P: ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: EthChainSpec<Header = Header>,
{
    let sphere_id = config.sphere_id;
    let sphere_chain_id = config.sphere_chain_id;
    if sphere_id == 0 {
        return Err(AttemptError::disable(eyre::eyre!(
            "Sphere ID must not be zero"
        )));
    }
    let l1_chain_id = l1.get_chain_id().await.map_err(classify_rpc_error)?;
    let expected_chain_id = sphere_primitives::constants::sphere_chain_id(l1_chain_id, sphere_id)
        .map_err(AttemptError::disable)?;
    if sphere_chain_id != expected_chain_id {
        return Err(AttemptError::disable(eyre::eyre!(
            "Sphere chain ID {sphere_chain_id} does not match Sphere {sphere_id} on Arc {l1_chain_id}"
        )));
    }

    let sphere_hash = provider
        .block_hash(GENESIS_BLOCK)
        .map_err(AttemptError::disable)?
        .ok_or_else(|| AttemptError::disable(eyre::eyre!("local Sphere genesis is unavailable")))?;
    let (arc, initial_token) =
        read_genesis(provider, evm_config, sphere_hash).map_err(AttemptError::disable)?;

    Ok(BootstrapContext {
        l1_chain_id,
        sphere: persistence::BlockRef::new(GENESIS_BLOCK, sphere_hash),
        arc,
        initial_token,
    })
}

/// Source determining whether a changed creation coordinate can be rediscovered.
#[derive(Clone, Copy)]
enum CreationSource {
    Discovery,
    Persistence,
}

/// Authenticate creation and the genesis anchor, then assemble bootstrap state.
async fn finish_bootstrap(
    context: BootstrapContext,
    l1: &DynProvider<Ethereum>,
    config: &CheckerConfig,
    creation: persistence::BlockRef,
    source: CreationSource,
) -> Result<Bootstrap, AttemptError> {
    authenticate_creation(l1, creation, config, context.initial_token, source).await?;
    if context.arc.number >= creation.number {
        return Err(AttemptError::disable(eyre::eyre!(
            "Sphere genesis Arc anchor {} must precede Portal creation block {}",
            context.arc.number,
            creation.number,
        )));
    }
    if !is_canonical(l1, context.arc, "Sphere genesis anchor").await? {
        return Err(AttemptError::disable(eyre::eyre!(
            "Sphere genesis Arc anchor is not canonical"
        )));
    }

    Ok(Bootstrap {
        identity: context.identity(config, creation),
        sphere: context.sphere,
        arc: persistence::BlockRef::from(context.arc),
    })
}

/// Read and validate Sphere genesis, returning its Arc anchor and initial token.
fn read_genesis<P>(
    provider: &P,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
    hash: B256,
) -> eyre::Result<(BlockNumHash, Address)>
where
    P: ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: EthChainSpec<Header = Header>,
{
    let chain_spec = provider.chain_spec();
    let snapshot = read_sphere_genesis(provider, hash, chain_spec.genesis_header(), evm_config)?;
    eyre::ensure!(
        !snapshot.arc_block_hash.is_zero(),
        "Sphere genesis has no Arc anchor"
    );
    eyre::ensure!(
        snapshot.processed_deposit_queue_hash.is_zero()
            && snapshot.processed_deposit_number == 0
            && snapshot.withdrawal_queue_hash.is_zero()
            && snapshot.withdrawal_batch_index == 0,
        "Sphere genesis contains prior bridge progress"
    );
    eyre::ensure!(
        !snapshot.default_fee_token.is_zero(),
        "Sphere genesis has no initial token"
    );
    eyre::ensure!(
        snapshot.initial_token_supply.is_zero(),
        "Sphere genesis initial token has nonzero supply"
    );
    Ok((
        BlockNumHash::new(snapshot.arc_block_number, snapshot.arc_block_hash),
        snapshot.default_fee_token,
    ))
}

/// Discover the unique creation coordinate from the RPC log index.
async fn discover_creation(
    provider: &DynProvider<Ethereum>,
    config: &CheckerConfig,
    anchor_number: u64,
) -> Result<persistence::BlockRef, AttemptError> {
    let head = provider
        .get_block_number()
        .await
        .map_err(classify_rpc_error)?;
    let filters = (0..=head).step_by(LOG_QUERY_BLOCKS as usize).map(|start| {
        Filter::new()
            .address(config.factory_address)
            .event_signature(SphereFactory::SphereCreated::SIGNATURE_HASH)
            .topic1(U256::from(config.sphere_id))
            .topic2(config.portal_address)
            .select(start..=start.saturating_add(LOG_QUERY_BLOCKS - 1).min(head))
    });
    let mut pages = stream::iter(filters)
        .map(|filter| async move { provider.get_logs(&filter).await.map_err(classify_rpc_error) })
        .buffer_unordered(LOG_QUERY_CONCURRENCY);
    let mut candidates = BTreeSet::new();
    while let Some(page) = pages.next().await {
        let page = page?;
        for log in page {
            if !log.removed {
                let number = log.block_number.ok_or_else(|| {
                    AttemptError::disable(eyre::eyre!(
                        "SphereCreated discovery result has no block number"
                    ))
                })?;
                let hash = log.block_hash.ok_or_else(|| {
                    AttemptError::disable(eyre::eyre!(
                        "SphereCreated discovery result has no block hash"
                    ))
                })?;
                candidates.insert(persistence::BlockRef::new(number, hash));
            }
        }
    }
    if candidates.is_empty() {
        return Err(AttemptError::retry(eyre::eyre!(
            "creation block is not yet available for Sphere {} and Portal {} after genesis anchor {}",
            config.sphere_id,
            config.portal_address,
            anchor_number,
        )));
    }
    if candidates.len() != 1 {
        return Err(AttemptError::disable(eyre::eyre!(
            "expected one creation block for Sphere {} and Portal {}, found {}",
            config.sphere_id,
            config.portal_address,
            candidates.len()
        )));
    }
    Ok(candidates
        .into_iter()
        .next()
        .expect("one creation coordinate was found"))
}

/// Require one matching `SphereCreated` event with authenticated receipt provenance.
async fn authenticate_creation(
    provider: &DynProvider<Ethereum>,
    creation: persistence::BlockRef,
    config: &CheckerConfig,
    initial_token: Address,
    source: CreationSource,
) -> Result<(), AttemptError> {
    let block = provider
        .get_block_by_number(creation.number.into())
        .hashes()
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| {
            AttemptError::retry(eyre::eyre!(
                "Portal creation block {} is unavailable",
                creation.number
            ))
        })?;
    let header = validate_rpc_header(block.header())?;
    let coordinate = persistence::BlockRef::from(header.block);
    if coordinate != creation {
        let error = eyre::eyre!(
            "Portal creation coordinate changed from block {} ({}) to block {} ({})",
            creation.number,
            creation.hash,
            coordinate.number,
            coordinate.hash
        );
        return Err(match source {
            CreationSource::Discovery => AttemptError::retry(error),
            CreationSource::Persistence => AttemptError::disable(error),
        });
    }
    let receipts = provider
        .get_block_receipts(BlockId::hash(creation.hash))
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| {
            AttemptError::retry(eyre::eyre!("Portal creation receipts are unavailable"))
        })?;
    sphere_l1::verify_receipts_against_header(
        coordinate.into(),
        header.receipts_root,
        header.logs_bloom,
        &receipts,
    )
    .map_err(AttemptError::disable)?;

    let mut creations = receipts
        .iter()
        .filter(|receipt| receipt.status())
        .flat_map(|receipt| receipt.logs())
        .filter(|log| log.address() == config.factory_address)
        .filter(|log| log.topic0() == Some(&SphereFactory::SphereCreated::SIGNATURE_HASH))
        .map(|log| {
            decode_event::<SphereFactory::SphereCreated>(
                &log.inner,
                "SphereCreated",
                creation.number,
            )
        })
        .collect::<eyre::Result<Vec<_>>>()
        .map_err(AttemptError::disable)?
        .into_iter()
        .filter(|event| {
            event.sphereId == config.sphere_id && event.portal == config.portal_address
        });
    let event = creations.next().ok_or_else(|| {
        AttemptError::disable(eyre::eyre!(
            "authenticated block has no matching SphereCreated event"
        ))
    })?;
    if creations.next().is_some() {
        return Err(AttemptError::disable(eyre::eyre!(
            "authenticated block has multiple matching SphereCreated events"
        )));
    }
    if event.initialToken != initial_token {
        return Err(AttemptError::disable(eyre::eyre!(
            "Portal initial token does not match Sphere genesis"
        )));
    }
    Ok(())
}

async fn is_canonical(
    provider: &DynProvider<Ethereum>,
    coordinate: BlockNumHash,
    name: &str,
) -> Result<bool, AttemptError> {
    let block = provider
        .get_block_by_number(coordinate.number.into())
        .hashes()
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| AttemptError::retry(eyre::eyre!("canonical {name} block is unavailable")))?;
    Ok(validate_rpc_header(block.header())?.block == coordinate)
}
