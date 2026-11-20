use alloy_primitives::Address;
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;

use alloy_chains::Chain;
use alloy_network::Ethereum;
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::TransportResult;

use alloy_consensus::Header;
use reth_chain_state::{CanonStateSubscriptions, PersistedBlockSubscriptions};
use reth_ethereum_primitives::Receipt;
use sphere_primitives::{SpherePrimitives, envelope::SphereTxEnvelope};
type Block = alloy_consensus::Block<SphereTxEnvelope>;
use reth_storage_api::{BlockReader, StateProviderFactory};

pub mod attestation;
mod encryption_key;
mod metrics;
pub mod monitor;
mod proofs;
mod rpc;
pub mod settlement;
mod settlement_manager;
pub mod withdrawals;
pub use monitor::{SphereMonitorConfig, SphereMonitorSharedState};
pub use settlement::{PortalSphereAnchor, resolve_portal_sphere_anchor};
pub use withdrawals::{
    DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES, DEFAULT_MAX_WITHDRAWAL_BATCH_GAS,
    MAX_WITHDRAWAL_BATCH_GAS, SharedWithdrawalStore, WithdrawalBatchLimits,
    WithdrawalProcessorConfig, WithdrawalStore,
};

pub use settlement::{BatchAnchor, BatchAnchorConfig, BatchData, BatchSubmitter, PreparedBatch};
pub use settlement_manager::SettlementManager;

pub use encryption_key::{
    EncryptionKeyProof, encryption_key_identity, prove_encryption_key_possession,
    register_encryption_key,
};

pub use proofs::{
    ProofCollectorConfig, ProofCollectorHandle, StoredBlockProof, create_proof_collector,
};

use crate::rpc::rpc_connection_config;

/// Returns the last committed block directly from the database snapshot.
pub trait DurableBlockReader {
    fn last_durable_block_num_hash(&self) -> eyre::Result<alloy_eips::NumHash>;
}

impl<N: reth_provider::providers::ProviderNodeTypes> DurableBlockReader
    for reth_provider::providers::BlockchainProvider<N>
{
    fn last_durable_block_num_hash(&self) -> eyre::Result<alloy_eips::NumHash> {
        use reth_storage_api::{BlockNumReader, DatabaseProviderFactory};
        let head = self.database_provider_ro()?.chain_info()?;
        Ok(alloy_eips::NumHash::new(head.best_number, head.best_hash))
    }
}

#[cfg(test)]
impl DurableBlockReader for reth_provider::test_utils::MockEthProvider<SpherePrimitives> {
    fn last_durable_block_num_hash(&self) -> eyre::Result<alloy_eips::NumHash> {
        use reth_storage_api::BlockNumReader;
        let head = self.chain_info()?;
        Ok(alloy_eips::NumHash::new(head.best_number, head.best_hash))
    }
}

/// Native Sphere node provider capabilities required by sequencer components.
///
/// This is a zero-method convenience trait over Reth's storage and canonical-state
/// interfaces. Keeping the bounds here lets sequencer components use native Arc
/// blocks and receipts without depending on an RPC representation.
pub trait SphereSequencerProvider:
    BlockReader<Block = Block, Header = Header, Transaction = SphereTxEnvelope, Receipt = Receipt>
    + CanonStateSubscriptions<Primitives = SpherePrimitives>
    + StateProviderFactory
    + DurableBlockReader
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> SphereSequencerProvider for T where
    T: BlockReader<
            Block = Block,
            Header = Header,
            Transaction = SphereTxEnvelope,
            Receipt = Receipt,
        > + CanonStateSubscriptions<Primitives = SpherePrimitives>
        + StateProviderFactory
        + DurableBlockReader
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Configuration for all sphere sequencer background tasks.
#[derive(Debug, Clone)]
pub struct SphereSequencerConfig {
    /// SpherePortal contract address on Arc L1.
    pub portal_address: Address,
    /// Arc L1 RPC URL.
    pub l1_rpc_url: String,
    /// Interval between WebSocket reconnection attempts for long-lived RPC clients.
    pub retry_connection_interval: Duration,
    /// Fallback interval for reconciling the canonical Sphere head.
    ///
    /// Canonical-state notifications normally trigger reconciliation immediately.
    pub sphere_poll_interval: Duration,
    /// How often the withdrawal processor polls the L1 queue.
    pub withdrawal_poll_interval: Duration,
    /// Gas and concurrency limits for withdrawal processing transactions.
    pub withdrawal_batch_limits: WithdrawalBatchLimits,
    /// SphereOutbox contract address on Sphere L2.
    pub outbox_address: Address,
    /// SphereInbox contract address on Sphere L2.
    pub inbox_address: Address,
    /// EIP-2935 history and safety-margin limits used by the batch submitter.
    pub batch_anchor_config: BatchAnchorConfig,
}

/// Handles returned by [`spawn_sphere_sequencer`] for managing background tasks.
pub struct SphereSequencerHandle {
    /// Join handle for the withdrawal processor task.
    pub withdrawal_handle: tokio::task::JoinHandle<()>,
    /// Join handle for the sphere monitor task (which also handles batch submission).
    pub monitor_handle: tokio::task::JoinHandle<()>,
}

/// Spawn all sphere sequencer background tasks.
///
/// Starts the settlement monitor and withdrawal processor.
/// - **Sphere monitor** — prepares the next persisted Sphere batch while the preceding batch is being
///   submitted to the SpherePortal. Submission remains ordered, and confirmed state only advances
///   after a successful L1 receipt.
/// - **Withdrawal processor** — polls the SpherePortal withdrawal queue on Arc L1 and calls
///   `processWithdrawals` for each pending withdrawal.
/// Both tasks share a single L1 provider and nonce manager to prevent signing/nonce contention
/// when submitting concurrent L1 transactions.
///
/// `shutdown` stops both tasks gracefully: it is observed at their poll boundaries, so an
/// in-flight L1 transaction resolves before teardown.
pub async fn spawn_sphere_sequencer<P>(
    config: SphereSequencerConfig,
    signer: PrivateKeySigner,
    sphere_provider: P,
    settlements: Option<SettlementManager>,
    shutdown: tokio_util::sync::CancellationToken,
) -> SphereSequencerHandle
where
    P: SphereSequencerProvider + PersistedBlockSubscriptions,
{
    // Build a single shared L1 provider with the sequencer wallet.
    // Both the batch submitter (inside the sphere monitor) and the withdrawal
    // processor use this provider, ensuring nonces are tracked in one place.
    let l1_provider = connect_l1_provider(
        &config.l1_rpc_url,
        config.retry_connection_interval,
        signer.clone(),
    )
    .await
    .expect("valid L1 RPC URL");
    let sequencer_address = signer.address();

    let withdrawal_store: SharedWithdrawalStore = Default::default();
    let withdrawal_notify = Arc::new(Notify::new());
    let withdrawal_repair_notify = Arc::new(Notify::new());

    let withdrawal_config = WithdrawalProcessorConfig {
        portal_address: config.portal_address,
        fallback_poll_interval: config.withdrawal_poll_interval,
        sequencer_address,
        batch_limits: config.withdrawal_batch_limits,
    };

    let monitor_config = SphereMonitorConfig {
        outbox_address: config.outbox_address,
        inbox_address: config.inbox_address,
        poll_interval: config.sphere_poll_interval,
        portal_address: config.portal_address,
        batch_anchor_config: config.batch_anchor_config,
        settlements,
    };
    let withdrawal_handle = withdrawals::spawn_withdrawal_processor(
        withdrawal_config,
        l1_provider.clone(),
        withdrawal_store.clone(),
        withdrawal_notify.clone(),
        withdrawal_repair_notify.clone(),
        shutdown.clone(),
    );
    let monitor_shared_state = SphereMonitorSharedState::new(
        withdrawal_store,
        withdrawal_notify,
        withdrawal_repair_notify,
    );
    let monitor_handle = monitor::spawn_sphere_monitor(
        monitor_config,
        sphere_provider,
        l1_provider,
        signer,
        monitor_shared_state,
        shutdown,
    );

    SphereSequencerHandle {
        withdrawal_handle,
        monitor_handle,
    }
}

/// Build the shared L1 provider used by all sequencer-side L1 transaction tasks.
async fn connect_l1_provider(
    l1_rpc_url: &str,
    retry_connection_interval: Duration,
    signer: PrivateKeySigner,
) -> TransportResult<DynProvider<Ethereum>> {
    let provider = ProviderBuilder::new_with_network::<Ethereum>()
        .wallet(signer)
        .connect_with_config(l1_rpc_url, rpc_connection_config(retry_connection_interval))
        .await?
        .erased();
    let l1_chain = Chain::from_id(provider.get_chain_id().await?);
    if !provider.client().is_local()
        && let Some(avg_block_time) = l1_chain.average_blocktime_hint()
    {
        provider
            .client()
            .set_poll_interval(avg_block_time.mul_f32(0.6));
    }

    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::Provider;
    use futures::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    async fn serve_block_number(
        stream: TcpStream,
        result: &'static str,
        close_after_response: bool,
    ) {
        let mut ws = accept_async(stream).await.unwrap();
        while let Some(message) = ws.next().await {
            let message = message.unwrap();
            let Message::Text(text) = message else {
                continue;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            let rpc_result = match request["method"].as_str() {
                Some("eth_chainId") => "0x4cef52",
                Some("eth_blockNumber") => result,
                _ => continue,
            };

            let response = json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": rpc_result,
            });
            ws.send(Message::Text(response.to_string().into()))
                .await
                .unwrap();

            if close_after_response && request["method"] == "eth_blockNumber" {
                let _ = ws.close(None).await;
                break;
            }
        }
    }

    #[tokio::test]
    async fn l1_provider_reconnects_after_wss_backend_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = connections.clone();

        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::SeqCst);

            // Drop the listener while closing the first connection so the
            // provider's immediate reconnect attempt fails. With the configured
            // 10ms retry interval below, it should recover quickly once the
            // listener comes back; Alloy's default 3s interval would miss the
            // test timeout.
            drop(listener);
            serve_block_number(first_stream, "0x1", true).await;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let listener = TcpListener::bind(addr).await.unwrap();
            let (second_stream, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::SeqCst);
            serve_block_number(second_stream, "0x2", false).await;
        });

        let provider =
            connect_l1_provider(&url, Duration::from_millis(10), PrivateKeySigner::random())
                .await
                .unwrap();

        assert_eq!(provider.get_block_number().await.unwrap(), 1);
        assert_eq!(
            provider.client().poll_interval(),
            Duration::from_millis(250),
            "chain metadata must not override Alloy's local transport interval"
        );

        let second_block = timeout(Duration::from_secs(2), provider.get_block_number())
            .await
            .expect("provider should reconnect after first WSS backend closes")
            .unwrap();
        assert_eq!(second_block, 2);
        assert!(
            connections.load(Ordering::SeqCst) >= 2,
            "provider should have opened a replacement WSS connection"
        );

        server.abort();
    }
}
