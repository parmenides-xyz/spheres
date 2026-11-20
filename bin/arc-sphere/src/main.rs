mod args;
mod engine;
mod node;
mod payload;
mod protocol_node;
mod protocol_validator;
mod startup;

use alloy_primitives::U256;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::Decodable;
use arc_execution_config::addresses_denylist::{
    AddressesDenylistConfig, DEFAULT_DENYLIST_ERC7201_BASE_SLOT,
};
use args::{SphereArgs, load_decryption_keys, load_sequencer_signer};
use clap::Parser;
use node::SphereDevNode;
use reth_chainspec::EthChainSpec;
use reth_cli_commands::{launcher::FnLauncher, node::NodeCommand};
use reth_cli_runner::CliRunner;
use reth_provider::{BlockNumReader, HeaderProvider, StateProviderFactory};
use sphere_chainspec::SphereChainSpecParser;
use sphere_chainspec::{SphereChainSpec, arc_chain_spec_for_l1};
use sphere_contracts::{
    SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS, SPHERE_TOKEN_ADDRESS, SpherePortal,
};
use sphere_l1::state::{EnabledTokenRegistry, L1StateProvider, L1StateProviderConfig};
use sphere_l1::{
    ArcStateExt, DepositQueue, EncryptionKeyRing, L1BlockTracker, L1StateCache, L1Subscriber,
    L1SubscriberConfig,
};
use sphere_node::{SphereEngine, SphereProtocolExecutorBuilder, pool::SpherePoolBuilder};
use sphere_payload::SpherePayloadFactory;
use sphere_primitives::constants::sphere_chain_id;
use sphere_sequencer::{SphereSequencerConfig, WithdrawalBatchLimits, spawn_sphere_sequencer};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

use tracing_subscriber::EnvFilter;

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    sphere_node::init_version_metadata();
    let mut command = NodeCommand::<SphereChainSpecParser, SphereArgs>::parse();
    let runner = CliRunner::try_default_runtime()?;
    if command.dev.dev {
        eyre::ensure!(
            command.ext.portal_address.is_none()
                && command.ext.l1_rpc_url.is_none()
                && !command.ext.enable_sequencer
                && command.ext.sequencer_manifest.is_none(),
            "--dev cannot be combined with L1 sequencing"
        );
        let launcher = FnLauncher::new::<SphereChainSpecParser, _>(async move |builder, _| {
            let handle = builder
                .node(SphereDevNode)
                .launch_with_debug_capabilities()
                .await?;
            handle.wait_for_node_exit().await
        });
        return runner.run_command_until_exit(|ctx| command.execute(ctx, launcher));
    }
    runner.run_command_until_exit(|ctx| async move {
        eyre::ensure!(
            command.ext.enable_sequencer || command.ext.sequencer_manifest.is_some(),
            "no Sphere chain advancement mechanism configured: enable a sequencer or configure P2P"
        );
        eyre::ensure!(
            (!command.rpc.http || command.rpc.http_addr.is_loopback())
                && (!command.rpc.ws || command.rpc.ws_addr.is_loopback())
                && command.rpc.auth_addr.is_loopback(),
            "operator RPC listeners must bind to loopback"
        );
        let args = &command.ext;
        let url = args
            .l1_rpc_url
            .as_deref()
            .ok_or_else(|| eyre::eyre!("--l1.rpc-url is required"))?;
        let portal_address = args
            .portal_address
            .ok_or_else(|| eyre::eyre!("--l1.portal-address is required"))?;
        let factory = args
            .factory_address
            .ok_or_else(|| eyre::eyre!("--l1.factory-address is required"))?;
        let l1 = ProviderBuilder::new().connect(url).await?.erased();
        let parent_id = l1.get_chain_id().await?;
        let portal = SpherePortal::new(portal_address, &l1);
        let sphere_id = portal.sphereId().call().await?;
        let chain_id = sphere_chain_id(parent_id, sphere_id)?;
        eyre::ensure!(
            command.chain.chain_id() == chain_id,
            "genesis chain ID does not match SpherePortal and Arc parent"
        );
        let anchor =
            sphere_l1::genesis::finalized_pre_creation_anchor(&l1, factory, portal_address, None)
                .await?;
        let header = alloy_consensus::Header::decode(&mut anchor.rlp.as_slice())?;
        let default_token = portal
            .enabledTokenAt(U256::ZERO)
            .block(alloy_eips::BlockId::number(anchor.block_number + 1))
            .call()
            .await?;
        eyre::ensure!(
            default_token == SPHERE_TOKEN_ADDRESS,
            "SpherePortal default fee token must be Arc USDC"
        );
        let creation = alloy_eips::BlockId::number(anchor.block_number + 1);
        let fee_owner = portal.admin().block(creation).call().await?;
        let fee_recipient = portal.leader().block(creation).call().await?;
        let (genesis, _) = sphere_node::genesis::l1_anchored_genesis(
            command.chain.genesis().clone(),
            &header,
            portal_address,
            default_token,
            fee_owner,
            fee_recipient,
        )?;
        let parent = arc_chain_spec_for_l1(parent_id)
            .ok_or_else(|| eyre::eyre!("no Arc chain spec for parent {parent_id}"))?;
        command.chain = Arc::new(SphereChainSpec::from_genesis_with_l1(genesis, &parent)?);
        let contract = parent
            .denylist_address()
            .ok_or_else(|| eyre::eyre!("no Arc denylist for parent {parent_id}"))?;
        let denylist =
            AddressesDenylistConfig::new(contract, DEFAULT_DENYLIST_ERC7201_BASE_SLOT, Vec::new());
        let p2p = match args.sequencer_manifest.as_ref() {
            Some(manifest) => {
                eyre::ensure!(
                    command.txpool.max_tx_input_bytes <= sphere_p2p::MAX_TRANSACTION_MESSAGE_SIZE,
                    "txpool transaction limit exceeds multi-sequencer P2P transaction limit"
                );
                Some(sphere_p2p::P2pConfig::load(
                    manifest,
                    args.p2p_key.as_ref().expect("manifest requires P2P key"),
                    args.secp256k1_key.as_ref(),
                    args.p2p_listen,
                    args.p2p_bypass_ip_check,
                    sphere_id,
                    args.sequencer_role,
                )?)
            }
            None => None,
        };
        let rpc_only = p2p.as_ref().is_some_and(sphere_p2p::P2pConfig::is_rpc_only);
        eyre::ensure!(
            !rpc_only
                || (args.sequencer_key_file.is_none()
                    && args.deposit_decryption_keys_file.is_none()),
            "rpc_only nodes must not hold sequencer or deposit decryption keys"
        );
        let signer = if rpc_only {
            None
        } else {
            Some(load_sequencer_signer(args.sequencer_key_file.as_deref()).await?)
        };
        if p2p.is_none()
            && let Some(signer) = signer.as_ref()
        {
            eyre::ensure!(
                portal.isSequencer(signer.address()).call().await?,
                "sequencer key is not registered on SpherePortal"
            );
        }
        let secret = signer
            .as_ref()
            .map(|signer| k256::SecretKey::from(signer.credential()));
        let keys = EncryptionKeyRing::new(
            secret
                .clone()
                .into_iter()
                .chain(load_decryption_keys(args.deposit_decryption_keys_file.as_deref()).await?),
        );
        let cache = L1StateCache::new();
        let interval = Duration::from_millis(args.l1_retry_connection_interval_ms);
        let reader = L1StateProvider::new(
            L1StateProviderConfig {
                chain_id: Some(parent_id),
                l1_rpc_url: url.to_string(),
                portal_address,
                retry_connection_interval: interval,
                ..Default::default()
            },
            cache.clone(),
            tokio::runtime::Handle::current(),
        )
        .await?;
        let mut payload = SpherePayloadFactory::new(args.sphere_batch_interval_blocks);
        if let Some(secret) = secret {
            payload = payload.with_withdrawal_reveal_encryptor(Arc::new(
                startup::SequencerWithdrawalRevealEncryptor::new(secret, sphere_id),
            ));
        }
        let node = protocol_node::SphereNode {
            pool: SpherePoolBuilder::new(None, denylist),
            payload,
            executor: SphereProtocolExecutorBuilder::new(reader, portal_address),
        };
        let max_response_size = command
            .rpc
            .rpc_max_response_size
            .get()
            .saturating_mul(1024 * 1024) as usize;
        let launcher =
            FnLauncher::new::<SphereChainSpecParser, SphereArgs>(async move |builder, args| {
                let tracker = L1BlockTracker::default();
                let observe = args.checker_mode == sphere_checker::CheckerMode::Observe;
                let checker = sphere_checker::CheckerExEx::new(sphere_checker::CheckerConfig {
                    l1_rpc_url: args
                        .l1_rpc_url
                        .clone()
                        .expect("L1 URL validated before launch"),
                    factory_address: factory,
                    portal_address,
                    sphere_id,
                    sphere_chain_id: chain_id,
                    database_path: builder.config().datadir().data_dir().join("checker"),
                    l1_block_tracker: tracker.clone(),
                });
                let handle = builder
                    .node(node)
                    .install_exex_if(observe, "sphere-checker", async move |ctx| {
                        Ok(checker.run(ctx))
                    })
                    .launch()
                    .await?;
                let provider = &handle.node.provider;
                let checkpoint = provider.latest()?.arc_block_number()?;
                let operational = startup::latest_operational_arc_block(provider)?;
                let deferred_work_start =
                    (operational < checkpoint).then(|| operational.saturating_add(1));
                if !rpc_only {
                    startup::resolve_and_seed_encryption_keys(
                        portal_address,
                        deferred_work_start,
                        &l1,
                        checkpoint,
                        &keys,
                    )
                    .await?;
                }
                let tokens = EnabledTokenRegistry::default();
                let at = alloy_eips::BlockId::number(checkpoint);
                if !l1
                    .get_code_at(portal_address)
                    .block_id(at)
                    .await?
                    .is_empty()
                {
                    let enabled = SpherePortal::new(portal_address, &l1)
                        .enabled_tokens_at(at)
                        .await?;
                    tokens.write().extend(enabled);
                }
                let queue = DepositQueue::new();
                sphere_l1::initialize_portal_pause(&l1, portal_address, &tracker).await;
                let tasks = &handle.node.task_executor;
                tasks.spawn_critical_task(
                    "portal-pause-watcher",
                    sphere_l1::watch_portal_pause(l1.clone(), portal_address, tracker.clone()),
                );
                let url = args.l1_rpc_url.expect("L1 URL validated before launch");
                let leadership = match p2p.as_ref() {
                    Some(config) => Some(
                        sphere_node::network::initialize_leadership(
                            config,
                            provider,
                            &l1,
                            portal_address,
                            checkpoint,
                        )
                        .await?,
                    ),
                    None => None,
                };
                let subscriber = L1Subscriber::new(
                    L1SubscriberConfig {
                        l1_rpc_url: url.clone(),
                        portal_address,
                        l1_fetch_concurrency: args.l1_fetch_concurrency,
                        retry_connection_interval: interval,
                        retain_portal_evidence: observe,
                        deferred_work_start,
                    },
                    provider.clone(),
                    queue.clone(),
                    tokens,
                    cache,
                    tracker.clone(),
                    leadership,
                    None,
                    (!rpc_only).then(|| keys.clone()),
                );
                tasks.spawn_critical_task("l1-block-subscriber", Box::pin(subscriber.run()));
                let cfg = sphere_rpc::RedactedRpcConfig {
                    listen_addr: ([0, 0, 0, 0], args.redacted_rpc_port).into(),
                    sphere_id,
                    chain_id,
                    max_auth_token_validity: Duration::from_secs(
                        args.redacted_rpc_max_auth_token_validity_secs,
                    ),
                    max_response_size,
                    sphere_portal: portal_address,
                };
                let rpc = sphere_node::rpc::SphereRpc::new(
                    handle
                        .node
                        .add_ons_handle
                        .rpc_registry
                        .eth_handlers()
                        .clone(),
                    cfg.clone(),
                    l1.clone(),
                );
                let addr = sphere_rpc::start_redacted_rpc(cfg, Arc::new(rpc)).await?;
                tracing::info!(%addr, "Redacted Sphere RPC server started");
                let seq_config = SphereSequencerConfig {
                    portal_address,
                    l1_rpc_url: url,
                    retry_connection_interval: interval,
                    sphere_poll_interval: Duration::from_secs(args.sphere_poll_interval_secs),
                    withdrawal_poll_interval: Duration::from_secs(
                        args.withdrawal_poll_interval_secs,
                    ),
                    withdrawal_batch_limits: WithdrawalBatchLimits {
                        max_batch_gas: args.withdrawal_max_batch_gas,
                        max_in_flight_batches: args.withdrawal_max_in_flight_batches,
                    },
                    outbox_address: SPHERE_OUTBOX_ADDRESS,
                    inbox_address: SPHERE_INBOX_ADDRESS,
                    batch_anchor_config: Default::default(),
                };
                let shutdown = CancellationToken::new();
                if let Some(config) = p2p {
                    let config =
                        config.with_storage_directory(handle.node.data_dir.data_dir().join("p2p"));
                    sphere_node::network::launch_roles(
                        config,
                        &l1,
                        parent_id,
                        portal_address,
                        provider.clone(),
                        handle.node.pool.clone(),
                        handle.node.add_ons_handle.beacon_engine_handle.clone(),
                        handle.node.payload_builder_handle.clone(),
                        handle.node.chain_spec(),
                        queue,
                        tracker,
                        keys,
                        signer.map(|s| (s, seq_config)),
                        tasks,
                    )
                    .await?;
                } else {
                    let signer = signer.expect("single-sequencer mode requires a signer");
                    let header = provider
                        .sealed_header(provider.best_block_number()?)?
                        .ok_or_else(|| eyre::eyre!("no latest block header"))?;
                    let engine = SphereEngine::new(
                        handle.node.chain_spec(),
                        handle.node.add_ons_handle.beacon_engine_handle.clone(),
                        handle.node.payload_builder_handle.clone(),
                        queue,
                        tracker,
                        header,
                        signer.address(),
                        keys,
                        portal_address,
                        None,
                    );
                    tasks.spawn_critical_task("sphere-engine", engine.run());
                    let seq_handle = spawn_sphere_sequencer(
                        seq_config,
                        signer,
                        provider.clone(),
                        None,
                        shutdown.clone(),
                    )
                    .await;
        // Critical task — node shuts down if any sequencer child exits.
        tasks.spawn_critical_task("sphere-monitor", async move {
            tokio::select! {
                res = seq_handle.withdrawal_handle => {
                    tracing::error!(target: "reth::cli", ?res, "Withdrawal processor task exited");
                }
                res = seq_handle.monitor_handle => {
                    tracing::error!(target: "reth::cli", ?res, "Sphere monitor task exited");
                }
            }
        });
                }
        // Flush unpersisted blocks on shutdown.
        let engine_shutdown = handle.node.add_ons_handle.engine_shutdown.clone();
        tasks.spawn_critical_with_graceful_shutdown_signal(
            "sphere-engine-shutdown",
            |shutdown| async move {
                let _guard = shutdown.await;
                tracing::info!(target: "reth::cli", "Shutdown signal received — flushing engine state");
                if let Some(done) = engine_shutdown.shutdown() {
                    let _ = done.await;
                }
            },
        );
                let result = handle.wait_for_node_exit().await;
                shutdown.cancel();
                result
            });
        command.execute(ctx, launcher).await
    })
}
