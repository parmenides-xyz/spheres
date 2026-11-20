use crate::{
    follower::PeerTipRegistry,
    pool::SpherePooledTransaction,
    replication::{BACKFILL_SERVE_QUEUE_CAPACITY, serve_backfill_requests},
    role::{
        EventSinks, LeaderSequencerDeps, RoleControllerContext, SharedRoleStatus,
        SphereSequencerAddOnsConfig, canonical_recovery_height, route_backfill_requests,
        route_backfill_responses, route_events_to_generations, run_role_controller,
    },
    settlement_attestation::AttestationContext,
};
use alloy_consensus::Header;
use alloy_eips::BlockNumberOrTag;
use alloy_network::Ethereum;
use alloy_primitives::Address;
use alloy_provider::{DynProvider, Provider};
use reth_chain_state::PersistedBlockSubscriptions;
use reth_node_api::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_provider::{BlockNumReader, HeaderProvider, StateProviderFactory};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::TransactionPool;
use sphere_chainspec::SphereChainSpec;
use sphere_contracts::SpherePortal;
use sphere_l1::{
    ArcStateExt, DepositQueue, EncryptionKeyRing, L1BlockTracker, LeaderTransition, LeadershipSink,
};
use sphere_p2p::{
    BackfillCommand, BackfillRequest, LeadershipSchedule, LeadershipState, P2pConfig, P2pNetworkId,
    SphereManifest, spawn_p2p,
};
use sphere_payload::SpherePayloadTypes;
use sphere_sequencer::{
    BatchAnchorConfig, SettlementManager, SphereSequencerConfig, SphereSequencerProvider,
    attestation::AttestationDomain,
};
use std::sync::Arc;
use tracing::{info, warn};
#[derive(Debug)]
struct ScheduleLeadershipSink {
    schedule: LeadershipSchedule,
    manifest: Arc<SphereManifest>,
    /// Finalized L1 height captured before subscriber startup. Historical identities are valid
    /// only while replaying transitions at or below this boundary.
    historical_replay_through: u64,
}

impl LeadershipSink for ScheduleLeadershipSink {
    fn apply_leader_transition(&self, transition: &LeaderTransition) -> eyre::Result<()> {
        let replaying_history = transition.activation_arc_block <= self.historical_replay_through;
        let leader = if replaying_history {
            self.manifest
                .leader_ed25519_by_secp256k1_address(transition.new_leader)
        } else {
            self.manifest
                .node_by_secp256k1_address(transition.new_leader)
                .map(|node| node.ed25519_public_key())
        }
        .ok_or_else(|| {
            let allowed = if replaying_history {
                "active or historical"
            } else {
                "active"
            };
            eyre::eyre!(
                "finalized portal leader {} (epoch {}) does not map to any {allowed} manifest identity",
                transition.new_leader,
                transition.epoch,
            )
        })?;
        self.schedule.publish(LeadershipState::new(
            transition.epoch,
            leader.clone(),
            transition.activation_arc_block,
        ))?;
        info!(
            target: "reth::cli",
            epoch = transition.epoch,
            leader = %transition.new_leader,
            peer = %leader,
            activation_arc_block = transition.activation_arc_block,
            "Observed finalized leadership transition"
        );
        Ok(())
    }
}

/// Install the manifest's temporary runtime authority before any role-dependent task starts.
///
/// The selected block must remain in the persisted canonical chain. Its historical state restores
/// the original Arc anchor and portal epoch, while the current portal snapshot distinguishes an
/// in-progress recovery from a completed directive left in the manifest after restart.
///
/// Canonical ancestry is intentionally a local restart check. Cross-node convergence still relies
/// on the operational invariant that every descendant was produced on the same chain by the
/// selected, non-equivocating recovery leader.
async fn install_manifest_forced_recovery<P>(
    provider: &P,
    l1_provider: &alloy_provider::DynProvider<Ethereum>,
    portal_address: Address,
    snapshot_anchor: u64,
    manifest: &SphereManifest,
    schedule: &LeadershipSchedule,
) -> eyre::Result<()>
where
    P: BlockNumReader + HeaderProvider<Header = Header> + StateProviderFactory,
{
    let Some(recovery) = manifest.forced_recovery() else {
        return Ok(());
    };
    let portal_leadership = schedule.latest().ok_or_else(|| {
        eyre::eyre!(
            "forced recovery requires a portal leadership snapshot at the local Arc checkpoint"
        )
    })?;
    let recovery_sphere_height =
        canonical_recovery_height(provider, recovery.recovery_block_hash())?;
    let recovery_anchor = provider
        .history_by_block_number(recovery_sphere_height)?
        .arc_block_number()?;
    let recovery_start_arc_block = recovery_anchor
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("forced recovery Arc anchor overflow"))?;

    let recovery_portal_epoch = if recovery_anchor == snapshot_anchor {
        portal_leadership.epoch
    } else {
        SpherePortal::new(portal_address, l1_provider)
            .leaderEpoch()
            .block(alloy_rpc_types_eth::BlockId::number(recovery_anchor))
            .call()
            .await
            .map_err(|err| {
                eyre::eyre!(
                    "failed to read portal epoch at recovery Arc block {recovery_anchor}: {err}"
                )
            })?
    };
    let recovery_epoch = recovery_portal_epoch
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("forced recovery epoch overflow"))?;

    if portal_leadership.epoch >= recovery_epoch {
        warn!(
            target: "reth::cli",
            leader = %recovery.leader(),
            recovery_epoch,
            recovery_sphere_height,
            recovery_sphere_hash = %recovery.recovery_block_hash(),
            snapshot_anchor,
            portal_epoch = portal_leadership.epoch,
            portal_activation_arc_block = portal_leadership.activation_arc_block,
            "Skipping completed manifest forced recovery; remove the stale directive"
        );
        metrics::counter!("sphere_forced_recovery_directives_total", "result" => "completed")
            .increment(1);
        return Ok(());
    }
    schedule.install_forced_recovery(
        recovery_epoch,
        recovery.leader().clone(),
        recovery.recovery_block_hash(),
        recovery_start_arc_block,
    )?;
    info!(
        target: "reth::cli",
        leader = %recovery.leader(),
        recovery_portal_epoch,
        recovery_sphere_height,
        recovery_sphere_hash = %recovery.recovery_block_hash(),
        recovery_start_arc_block,
        resumed = snapshot_anchor >= recovery_start_arc_block,
        "Installed manifest forced recovery"
    );
    Ok(())
}

/// Seed the leadership schedule from the portal snapshot at the local Arc anchor.
///
/// `snapshot_anchor` is the sphere's persisted checkpoint (or the genesis anchor for a fresh sphere).
async fn seed_leadership_schedule(
    l1_provider: &alloy_provider::DynProvider<Ethereum>,
    portal_address: Address,
    snapshot_anchor: u64,
    manifest: &Arc<SphereManifest>,
    schedule: &LeadershipSchedule,
) -> eyre::Result<()> {
    let block_id = alloy_rpc_types_eth::BlockId::number(snapshot_anchor);
    let portal_code = if snapshot_anchor == 0 {
        Default::default()
    } else {
        l1_provider
            .get_code_at(portal_address)
            .block_id(block_id)
            .await
            .map_err(|err| {
                eyre::eyre!(
                    "failed to check portal {portal_address} deployment at L1 block \
                     {snapshot_anchor}: {err}"
                )
            })?
    };
    if portal_code.is_empty() {
        info!(
            target: "reth::cli",
            snapshot_anchor,
            "Portal is not deployed at the local Arc anchor; leadership stays fenced until \
             the creation block replays"
        );
        return Ok(());
    }

    let portal = SpherePortal::new(portal_address, l1_provider);
    // Read the complete transition atomically at the authenticated snapshot.
    let (leader, epoch, activation) = l1_provider
        .multicall()
        .block(block_id)
        .add(portal.leader())
        .add(portal.leaderEpoch())
        .add(portal.leaderActivationArcBlock())
        .aggregate()
        .await?;
    eyre::ensure!(
        !leader.is_zero(),
        "portal {portal_address} has no leader at finalized L1 snapshot block {snapshot_anchor}"
    );
    let leader_peer = manifest
        .leader_ed25519_by_secp256k1_address(leader)
        .ok_or_else(|| {
            eyre::eyre!(
                "finalized portal leader {leader} (epoch {epoch}) does not map to any active or \
             historical manifest identity; refusing to start without an authenticated leader"
            )
        })?;
    let leadership = LeadershipState::new(epoch, leader_peer.clone(), activation);
    schedule.publish(leadership)?;
    info!(
        target: "reth::cli",
        snapshot_anchor,
        %leader,
        epoch,
        activation_arc_block = activation,
        peer = %leader_peer,
        "Bootstrapped leadership from the finalized portal snapshot"
    );
    Ok(())
}

pub async fn initialize_leadership<P: SphereSequencerProvider>(
    config: &P2pConfig,
    provider: &P,
    l1_provider: &DynProvider<Ethereum>,
    portal_address: Address,
    snapshot_anchor: u64,
) -> eyre::Result<Arc<dyn LeadershipSink>> {
    let schedule = config.leadership();
    let historical_replay_through = l1_provider
        .get_header_by_number(BlockNumberOrTag::Finalized)
        .await?
        .ok_or_else(|| eyre::eyre!("L1 finalized block is not available"))?
        .number;
    seed_leadership_schedule(
        l1_provider,
        portal_address,
        snapshot_anchor,
        config.manifest(),
        &schedule,
    )
    .await?;
    schedule.record_applied_anchor(snapshot_anchor);
    install_manifest_forced_recovery(
        provider,
        l1_provider,
        portal_address,
        snapshot_anchor,
        config.manifest(),
        &schedule,
    )
    .await?;
    Ok(Arc::new(ScheduleLeadershipSink {
        schedule,
        manifest: config.manifest().clone(),
        historical_replay_through,
    }))
}

pub async fn launch_roles<P, Pool>(
    config: P2pConfig,
    l1_provider: &DynProvider<Ethereum>,
    l1_chain_id: u64,
    portal_address: Address,
    provider: P,
    pool: Pool,
    engine_handle: ConsensusEngineHandle<SpherePayloadTypes>,
    payload_builder: PayloadBuilderHandle<SpherePayloadTypes>,
    chain_spec: Arc<SphereChainSpec>,
    deposit_queue: DepositQueue,
    l1_block_tracker: L1BlockTracker,
    encryption_keys: EncryptionKeyRing,
    sequencer: Option<(alloy_signer_local::PrivateKeySigner, SphereSequencerConfig)>,
    task_executor: &TaskExecutor,
) -> eyre::Result<SharedRoleStatus>
where
    P: SphereSequencerProvider + PersistedBlockSubscriptions,
    Pool: TransactionPool<Transaction = SpherePooledTransaction> + 'static,
{
    let network_id = P2pNetworkId::new(l1_chain_id, portal_address);
    let attestation_domain = AttestationDomain {
        l1_chain_id,
        portal_address,
        sphere_id: config.sphere_id(),
    };
    let pinned_sequencer_set_version =
        crate::settlement_attestation::validate_registered_sequencer_set(
            config.manifest(),
            portal_address,
            l1_provider,
        )
        .await?;
    let attestation = AttestationContext::new(
        attestation_domain,
        pinned_sequencer_set_version,
        config.block_attestation_signer(),
        config.block_attestation_addresses(),
        l1_provider.clone(),
        BatchAnchorConfig::default(),
    );
    let schedule = config.leadership();
    let local_ed25519_public_key = config.ed25519_public_key();
    let individual_signer = config.block_attestation_signer();
    let (backfill_requests_tx, backfill_requests_rx) =
        tokio::sync::mpsc::channel(BACKFILL_SERVE_QUEUE_CAPACITY);
    let (sinks, commands, backfill_commands) =
        launch_p2p_network(config, network_id, task_executor, backfill_requests_tx)?;

    let settlements = attestation.signer.clone().map(|signer| {
        SettlementManager::new(
            attestation.domain,
            attestation.pinned_sequencer_set_version,
            signer,
            attestation.addresses.clone(),
            attestation.l1_provider.clone(),
            attestation.anchor_config,
            commands.clone(),
        )
    });

    let role_status: SharedRoleStatus = Default::default();
    let peer_tips = PeerTipRegistry::default();
    task_executor.spawn_critical_task(
        "sphere-backfill-server",
        serve_backfill_requests(
            provider.clone(),
            backfill_commands.clone(),
            backfill_requests_rx,
            None,
        ),
    );
    let sequencer = sequencer.map(|(sequencer_signer, sequencer_config)| LeaderSequencerDeps {
        config: SphereSequencerAddOnsConfig {
            sequencer_signer,
            l1_transaction_signer: individual_signer,
        },
        sequencer_config,
        proof_collector: None,
    });
    let context = RoleControllerContext {
        local_ed25519_public_key,
        schedule,
        provider,
        pool,
        engine_handle,
        payload_builder,
        chain_spec,
        deposit_queue,
        l1_block_tracker,
        encryption_keys,
        commands,
        backfill_commands,
        attestation,
        settlements,
        portal_address,
        sequencer,
        peer_tips,
        status: role_status.clone(),
    };
    task_executor.spawn_critical_task(
        "sphere-role-controller",
        run_role_controller(context, sinks),
    );
    Ok(role_status)
}
/// Start the Commonware network and the long-lived P2P event demultiplexer.
///
/// Role-specific consumers are attached later by the role controller through the returned
/// [`EventSinks`]. Generic events and typed backfill ports are routed for the process lifetime.
fn launch_p2p_network(
    config: P2pConfig,
    network_id: P2pNetworkId,
    task_executor: &reth_tasks::TaskExecutor,
    backfill_requests: tokio::sync::mpsc::Sender<BackfillRequest>,
) -> eyre::Result<(
    EventSinks,
    tokio::sync::mpsc::Sender<sphere_p2p::P2pCommand>,
    tokio::sync::mpsc::Sender<BackfillCommand>,
)> {
    let handle = spawn_p2p(config, network_id)?;
    let sphere_p2p::P2pHandleParts {
        shutdown: shutdown_token,
        mut stopped,
        thread,
        commands,
        events,
        backfill,
    } = handle.into_parts();

    let sinks = EventSinks::default();
    task_executor.spawn_critical_task(
        "sphere-p2p-event-router",
        route_events_to_generations(events, sinks.clone()),
    );
    task_executor.spawn_critical_task(
        "sphere-p2p-backfill-request-router",
        route_backfill_requests(backfill.requests, backfill_requests),
    );
    task_executor.spawn_critical_task(
        "sphere-p2p-backfill-response-router",
        route_backfill_responses(backfill.responses, sinks.clone()),
    );

    task_executor.spawn_critical_with_graceful_shutdown_signal(
            "sphere-p2p",
            |shutdown| async move {
                let unexpected_exit = tokio::select! {
                    guard = shutdown => {
                        let _guard = guard;
                        shutdown_token.cancel();
                        match stopped.await {
                            Ok(Ok(())) => info!(target: "reth::cli", "P2P runtime stopped"),
                            Ok(Err(err)) => tracing::error!(target: "reth::cli", %err, "P2P runtime failed during shutdown"),
                            Err(err) => tracing::error!(target: "reth::cli", %err, "P2P runtime completion channel closed during shutdown"),
                        }
                        None
                    }
                    result = &mut stopped => {
                        Some(match result {
                            Ok(Ok(())) => "P2P runtime stopped unexpectedly".to_string(),
                            Ok(Err(err)) => format!("P2P runtime failed: {err}"),
                            Err(err) => format!("P2P runtime completion channel closed unexpectedly: {err}"),
                        })
                    }
                };

                match tokio::task::spawn_blocking(move || thread.join()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => panic!("P2P runtime thread panicked"),
                    Err(err) => panic!("Failed joining P2P runtime thread: {err}"),
                }

                if let Some(reason) = unexpected_exit {
                    panic!("{reason}");
                }
            },
        );
    Ok((sinks, commands, backfill.commands))
}
