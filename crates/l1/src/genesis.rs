use alloy_consensus::BlockHeader as _;
use alloy_eips::BlockNumberOrTag;
use alloy_network::Ethereum;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::BlockId;
use eyre::{WrapErr as _, ensure, eyre};
use sphere_contracts::{SphereFactory, SpherePortal};
use std::time::Duration;

const LOG_QUERY_BLOCK_CHUNK: u64 = 5_000;

/// Finds the block of the single SphereCreated event for `sphere_id` and `portal` in
/// `from_block..=snapshot_block`.
///
/// Pass `0` when the creation block is unknown. Scanning from genesis issues one log query
/// per 5,000 blocks, so callers that already know the creation block should start there.
pub async fn find_sphere_deployment_block<P: Provider<Ethereum>>(
    provider: &P,
    factory: Address,
    sphere_id: u32,
    portal: Address,
    from_block: u64,
    snapshot_block: u64,
) -> eyre::Result<u64> {
    let events = SphereFactory::new(factory, provider)
        .SphereCreated_filter()
        .topic1(U256::from(sphere_id))
        .topic2(portal)
        .from_block(from_block)
        .to_block(snapshot_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning SphereFactory SphereCreated events")?;

    eyre::ensure!(
        events.len() == 1,
        "expected exactly one SphereCreated event for Sphere {sphere_id} and portal {portal}, found {}",
        events.len()
    );
    let (event, log) = &events[0];
    eyre::ensure!(
        event.sphereId == sphere_id && event.portal == portal,
        "SphereCreated event does not match Sphere {sphere_id} and portal {portal}"
    );
    eyre::ensure!(!log.removed, "SphereCreated query returned a removed log");
    let block_number = log
        .block_number
        .ok_or_else(|| eyre!("SphereCreated log is missing its block number"))?;
    let block_hash = log
        .block_hash
        .ok_or_else(|| eyre!("SphereCreated log is missing its block hash"))?;
    let header = provider
        .get_header_by_number(block_number.into())
        .await
        .wrap_err_with(|| format!("failed reading SphereCreated block {block_number}"))?
        .ok_or_else(|| eyre!("SphereCreated block {block_number} was not found"))?;
    eyre::ensure!(
        header.number() == block_number && header.hash == block_hash,
        "SphereCreated log block ({block_number}, {block_hash}) does not match canonical header ({}, {})",
        header.number(),
        header.hash
    );
    Ok(block_number)
}

pub struct PreCreationAnchor {
    pub block_number: u64,
    pub hash: B256,
    pub rlp: Vec<u8>,
}

pub async fn finalized_pre_creation_anchor<P: Provider<Ethereum>>(
    provider: &P,
    factory: Address,
    portal: Address,
    expected_creation_block: Option<u64>,
) -> eyre::Result<PreCreationAnchor> {
    let finalized_header = provider
        .get_header_by_number(BlockNumberOrTag::Finalized)
        .await
        .wrap_err("failed to fetch finalized Arc L1 block")?
        .ok_or_else(|| eyre!("Arc L1 returned no finalized block"))?;
    let finalized_block = finalized_header.number();
    if let Some(expected) = expected_creation_block {
        ensure!(
            expected <= finalized_block,
            "SpherePortal creation block {expected} is not finalized yet (finalized Arc block: {finalized_block})"
        );
    }
    let finalized_block_id = BlockId::number(finalized_block);

    ensure!(
        !provider
            .get_code_at(portal)
            .block_id(finalized_block_id)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to fetch code for portal {portal} at finalized block {finalized_block}"
                )
            })?
            .is_empty(),
        "portal {portal} has no code at finalized Arc block {finalized_block}; check --arc-portal and --l1-rpc-url"
    );

    let sphere_id = SpherePortal::new(portal, provider)
        .sphereId()
        .block(finalized_block_id)
        .call()
        .await
        .wrap_err_with(|| {
            format!("failed to read Sphere ID from portal {portal} at block {finalized_block}")
        })?;
    // A known creation block bounds the scan; the code checks below still prove that the
    // portal was deployed in exactly that block.
    let creation_block = find_sphere_deployment_block(
        provider,
        factory,
        sphere_id,
        portal,
        expected_creation_block.unwrap_or(0),
        finalized_block,
    )
    .await?;
    if let Some(expected) = expected_creation_block {
        ensure!(
            creation_block == expected,
            "SphereCreated event is in block {creation_block}, but the creation receipt reported block {expected}"
        );
    }
    let anchor_block = creation_block.checked_sub(1).ok_or_else(|| {
        eyre!("portal {portal} exists at genesis, so no pre-creation anchor is available")
    })?;
    ensure!(
        provider
            .get_code_at(portal)
            .number(anchor_block)
            .await
            .wrap_err_with(|| {
                format!("failed to fetch portal code at Arc anchor block {anchor_block}")
            })?
            .is_empty(),
        "portal {portal} already has code at proposed pre-creation anchor block {anchor_block}"
    );
    ensure!(
        !provider
            .get_code_at(portal)
            .number(creation_block)
            .await
            .wrap_err_with(|| {
                format!("failed to fetch portal code at creation block {creation_block}")
            })?
            .is_empty(),
        "portal {portal} has no code at SphereCreated block {creation_block}"
    );

    let anchor_header_response = provider
        .get_header_by_number(anchor_block.into())
        .await
        .wrap_err_with(|| format!("failed to fetch Arc anchor header {anchor_block}"))?
        .ok_or_else(|| eyre!("Arc anchor header {anchor_block} was not found"))?;
    ensure!(
        anchor_header_response.number() == anchor_block,
        "Arc RPC returned header {} for requested anchor block {anchor_block}",
        anchor_header_response.number()
    );
    let response_hash = anchor_header_response.hash;
    let header_rlp = alloy_rlp::encode(anchor_header_response.inner);
    let anchor_hash = keccak256(&header_rlp);
    ensure!(
        anchor_hash == response_hash,
        "Arc anchor header RLP hash {anchor_hash} does not match RPC block hash {response_hash}"
    );
    println!(
        "Derived pre-creation Arc anchor block {anchor_block} (hash: {anchor_hash}) for portal {portal}"
    );
    Ok(PreCreationAnchor {
        block_number: anchor_block,
        hash: anchor_hash,
        rlp: header_rlp,
    })
}

pub async fn wait_for_finalized_pre_creation_anchor<P: Provider<Ethereum>>(
    provider: &P,
    factory: Address,
    portal: Address,
    creation_block: u64,
) -> eyre::Result<PreCreationAnchor> {
    const ATTEMPTS: usize = 600;
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    for _ in 0..ATTEMPTS {
        let finalized = provider
            .get_header_by_number(BlockNumberOrTag::Finalized)
            .await
            .wrap_err("failed to fetch finalized Arc L1 block")?
            .ok_or_else(|| eyre!("Arc L1 returned no finalized block"))?;
        if finalized.number() >= creation_block {
            return finalized_pre_creation_anchor(provider, factory, portal, Some(creation_block))
                .await;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    Err(eyre!(
        "SpherePortal creation block {creation_block} was not finalized within {} seconds",
        ATTEMPTS as u128 * POLL_INTERVAL.as_millis() / 1_000
    ))
}
