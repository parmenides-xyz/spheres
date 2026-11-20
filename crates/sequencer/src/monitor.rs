//! Sphere L2 block monitor with integrated batch submission.
//!
//! Watches the **Sphere L2** chain for new blocks, collecting withdrawal events and
//! reading on-chain state to produce [`BatchData`]. Emits one L1 batch
//! submission for each L2 `BatchFinalized` boundary.
//!
//! ## Batch boundaries
//!
//! The payload builder records batch boundaries by appending
//! `SphereOutbox.finalizeWithdrawalBatch` to final blocks only. The monitor treats
//! those `BatchFinalized` events as authoritative and emits exactly one
//! `submitBatch` per boundary, in order.
//!
//! ## EIP-2935 and ancestry mode
//!
//! The portal verifies `arcBlockNumber` via EIP-2935, which stores the last 8192
//! block hashes. When `arcBlockNumber` is within this window the batch submitter
//! uses **direct mode** (reading the hash straight from EIP-2935). If the sphere
//! falls behind (e.g. sequencer downtime >2 hours), the submitter automatically
//! switches to **ancestry mode** for that batch: it supplies a recent L1 block
//! number that IS within the EIP-2935 window, and the proof must include a
//! block header chain linking that anchor back to `arcBlockNumber`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_network::Ethereum;
use alloy_primitives::{Address, B256};
use alloy_provider::DynProvider;
use alloy_signer_local::PrivateKeySigner;
use eyre::{Result, WrapErr};
use futures::StreamExt;
use reth_chain_state::PersistedBlockSubscriptions;
use sphere_prover::VerifierMode;
use tokio::sync::{Notify, mpsc};
use tokio_util::{sync, task::AbortOnDropHandle};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    SettlementManager, SphereSequencerProvider,
    attestation::SettlementCertificate,
    resolve_portal_sphere_anchor,
    settlement::{
        BatchAnchorConfig, BatchData, BatchSubmitError, BatchSubmitter, FinalizedBatchLog,
        PreparedBatch, SphereBlockSnapshot, WithdrawalPage, fetch_finalized_batch,
        fetch_finalized_batch_boundaries, read_sphere_block_snapshot,
    },
    withdrawals::SharedWithdrawalStore,
};
use sphere_contracts::{self as abi, NO_QUEUE_INDEX};

/// Maximum number of times to retry a failed batch submission before restarting the pipeline.
const MAX_RETRIES: u32 = 3;

/// Initial delay between retries (doubles on each attempt).
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Backoff before rebuilding the monitor after a start or run failure.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// Configuration for the [`SphereMonitor`].
#[derive(Debug, Clone)]
pub struct SphereMonitorConfig {
    /// SphereOutbox contract address on Sphere L2.
    pub outbox_address: Address,
    /// SphereInbox contract address on Sphere L2.
    pub inbox_address: Address,
    /// Fallback interval for reconciling the canonical head when no notification arrives.
    pub poll_interval: Duration,
    /// SpherePortal contract address on Arc L1.
    pub portal_address: Address,
    /// EIP-2935 history and safety-margin limits used by the batch submitter.
    pub batch_anchor_config: BatchAnchorConfig,
    /// Settlement preparation for a P2P leader generation.
    pub settlements: Option<SettlementManager>,
}

/// Withdrawal state shared between the sphere monitor and withdrawal processor.
#[derive(Clone)]
pub struct SphereMonitorSharedState {
    withdrawal_store: SharedWithdrawalStore,
    withdrawal_notify: Arc<Notify>,
    repair_notify: Arc<Notify>,
}

impl SphereMonitorSharedState {
    /// Create the shared withdrawal state used by the sphere monitor.
    pub fn new(
        withdrawal_store: SharedWithdrawalStore,
        withdrawal_notify: Arc<Notify>,
        repair_notify: Arc<Notify>,
    ) -> Self {
        Self {
            withdrawal_store,
            withdrawal_notify,
            repair_notify,
        }
    }
}

/// Monitors the Sphere L2 chain for new finalized batch boundaries and submits
/// them to the SpherePortal on L1.
///
/// Prepared batches are submitted in order. A submission failure rebuilds the monitor and its
/// preparation pipeline from the portal-confirmed checkpoint.
///
/// At startup, a non-zero portal anchor must resolve to a canonical local block. Startup fails
/// closed if that anchor is unavailable or inconsistent instead of silently replaying from genesis.
pub struct SphereMonitor<P: SphereSequencerProvider> {
    config: SphereMonitorConfig,
    /// Metrics for sphere observation and L1 batch submission.
    metrics: crate::metrics::SphereMonitorMetrics,
    /// Native provider for canonical Arc blocks, transactions, and receipts.
    provider: P,
    /// Shared store for withdrawal data, written here and consumed by the
    /// [`WithdrawalProcessor`](crate::withdrawals::WithdrawalProcessor) on **Arc L1**.
    withdrawal_store: SharedWithdrawalStore,
    /// Batch submitter for posting batches to the SpherePortal on **Arc L1**.
    batch_submitter: Arc<BatchSubmitter>,
    /// Notifier for the withdrawal processor — signalled after each successful
    /// batch submission so it can process newly enqueued withdrawal slots.
    withdrawal_notify: Arc<Notify>,
    /// Notifier from the withdrawal processor when the current portal head slot
    /// is missing or stale and its bounded recovery page must be refilled.
    repair_notify: Arc<Notify>,
    /// Commitments used to seed the preparation task.
    preparation_cursor: BatchCursor,
    /// Persisted Sphere head observed by preparation.
    observed_sphere_block: Arc<AtomicU64>,
    /// Sphere height confirmed by submission and observed by preparation.
    submitted_sphere_block: Arc<AtomicU64>,
}

/// Commitments at the tail of the prepared batch chain.
#[derive(Debug, Clone, Copy)]
struct BatchCursor {
    sphere_height: u64,
    block_hash: B256,
    processed_deposit_hash: B256,
    processed_deposit_number: u64,
    processed_token_count: u64,
}

impl BatchCursor {
    fn advance(&mut self, batch: &BatchData) {
        self.sphere_height = batch.sphere_height;
        self.block_hash = batch.next_block_hash;
        self.processed_deposit_hash = batch.next_processed_deposit_hash;
        self.processed_deposit_number = batch.next_deposit_number;
        self.processed_token_count = batch.next_processed_token_count;
    }
}

/// A batch whose anchor and settlement certificate are ready for L1 submission.
#[derive(Debug)]
struct ReadyBatch {
    prepared: PreparedBatch,
    verifier_mode: VerifierMode,
    certificate: Option<SettlementCertificate>,
    withdrawals: Vec<abi::Withdrawal>,
}

/// Discovers persisted batch boundaries and prepares the next submission independently of L1.
struct BatchPreparer<P: SphereSequencerProvider> {
    config: SphereMonitorConfig,
    metrics: crate::metrics::SphereMonitorMetrics,
    provider: P,
    batch_submitter: Arc<BatchSubmitter>,
    cursor: BatchCursor,
    latest_observed_sphere_block: u64,
    observed_sphere_block: Arc<AtomicU64>,
    submitted_sphere_block: Arc<AtomicU64>,
}

impl<P> BatchPreparer<P>
where
    P: SphereSequencerProvider + PersistedBlockSubscriptions,
{
    async fn run(mut self, ready_tx: mpsc::Sender<ReadyBatch>) -> Result<()> {
        // Subscribe before reading the head so a block persisted during startup cannot be missed.
        let mut persisted = self.provider.persisted_block_stream();
        let mut fallback = tokio::time::interval(self.config.poll_interval);

        loop {
            self.process_available_blocks(&ready_tx).await?;

            tokio::select! {
                _ = fallback.tick() => {}
                notification = persisted.next() => {
                    let Some(_tip) = notification else {
                        return Err(eyre::eyre!("persisted sphere block notification stream closed"));
                    };
                }
            }
        }
    }
}

impl<P: SphereSequencerProvider> SphereMonitor<P> {
    /// Create a new sphere monitor with integrated batch submission.
    ///
    /// Uses the node's native provider for Sphere data and creates a [`BatchSubmitter`] backed by
    /// the shared `l1_provider` for posting batches to the SpherePortal on L1.
    pub async fn new(
        config: SphereMonitorConfig,
        provider: P,
        l1_provider: DynProvider<Ethereum>,
        signer: PrivateKeySigner,
        withdrawal_store: SharedWithdrawalStore,
        withdrawal_notify: Arc<Notify>,
        repair_notify: Arc<Notify>,
    ) -> Result<Self> {
        Self::new_with_provider(
            config,
            provider,
            l1_provider,
            Some(signer),
            withdrawal_store,
            withdrawal_notify,
            repair_notify,
        )
        .await
    }

    async fn new_with_provider(
        config: SphereMonitorConfig,
        provider: P,
        l1_provider: DynProvider<Ethereum>,
        signer: Option<PrivateKeySigner>,
        withdrawal_store: SharedWithdrawalStore,
        withdrawal_notify: Arc<Notify>,
        repair_notify: Arc<Notify>,
    ) -> Result<Self> {
        let metrics = crate::metrics::SphereMonitorMetrics::default();
        let batch_submitter = Arc::new(BatchSubmitter::with_optional_signer_and_anchor_config(
            config.portal_address,
            l1_provider,
            signer,
            config.batch_anchor_config,
        ));
        let portal_anchor = resolve_portal_sphere_anchor(
            &provider,
            config.portal_address,
            batch_submitter.l1_provider(),
        )
        .await
        .wrap_err(
            "failed to resolve portal-confirmed sphere block during sphere monitor startup",
        )?;
        let prev_sphere_block_hash = portal_anchor.block_hash;
        let last_submitted_sphere_block = portal_anchor.block_number;
        let previous_snapshot = Self::snapshot_at_or_genesis(
            &provider,
            config.inbox_address,
            last_submitted_sphere_block,
        )?;
        let prev_processed_deposit_hash = previous_snapshot.processed_deposit_hash;
        let prev_processed_deposit_number = previous_snapshot.processed_deposit_number;
        let prev_processed_token_count = previous_snapshot.processed_token_count;

        info!(
            last_submitted_sphere_block,
            %prev_sphere_block_hash,
            %prev_processed_deposit_hash,
            prev_processed_deposit_number,
            prev_processed_token_count,
            "Initialized from portal state"
        );

        metrics
            .latest_sphere_block_observed
            .set(last_submitted_sphere_block as f64);
        metrics
            .latest_sphere_block_submitted_to_l1
            .set(last_submitted_sphere_block as f64);
        metrics.sphere_to_l1_submission_lag_blocks.set(0.0);

        let observed_sphere_block = Arc::new(AtomicU64::new(last_submitted_sphere_block));
        let submitted_sphere_block = Arc::new(AtomicU64::new(last_submitted_sphere_block));
        let preparation_cursor = BatchCursor {
            sphere_height: last_submitted_sphere_block,
            block_hash: prev_sphere_block_hash,
            processed_deposit_hash: prev_processed_deposit_hash,
            processed_deposit_number: prev_processed_deposit_number,
            processed_token_count: prev_processed_token_count,
        };
        let monitor = Self {
            config,
            metrics,
            provider,
            withdrawal_store,
            batch_submitter,
            withdrawal_notify,
            repair_notify,
            preparation_cursor,
            observed_sphere_block,
            submitted_sphere_block,
        };

        // Restore pending withdrawal data from sphere L2 events so the
        // withdrawal processor can pick up where it left off.
        monitor
            .restore_pending_withdrawals_from_chain()
            .await
            .wrap_err("failed to restore pending withdrawals during sphere monitor startup")?;

        Ok(monitor)
    }

    /// Run the monitor loop. This method never returns under normal operation.
    ///
    /// Reconciles the persisted head at startup and after every persisted-block notification.
    #[instrument(skip_all, fields(
        outbox = %self.config.outbox_address,
        inbox = %self.config.inbox_address,
    ))]
    /// Returns `Ok(())` only when `shutdown` fires; the token is observed at the poll
    /// boundary so an in-flight batch submission resolves before teardown.
    pub async fn run(mut self, shutdown: &sync::CancellationToken) -> Result<()>
    where
        P: PersistedBlockSubscriptions,
    {
        info!("Native sphere monitor started");

        let preparation = self.batch_preparer();
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let mut preparation_task = AbortOnDropHandle::new(tokio::spawn(preparation.run(ready_tx)));

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    info!("Sphere monitor observed shutdown");
                    return Ok(());
                }
                joined = &mut preparation_task => {
                    return joined.wrap_err("batch preparation task panicked")?;
                }
                _ = self.repair_notify.notified() => {
                    self.refill_withdrawal_cache().await;
                }
                ready = ready_rx.recv() => {
                    let Some(ready) = ready else {
                        return Err(eyre::eyre!("batch preparation channel closed"));
                    };
                    self.submit_ready_batch(ready).await?;
                }
            }
        }
    }

    fn batch_preparer(&self) -> BatchPreparer<P> {
        BatchPreparer {
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            provider: self.provider.clone(),
            batch_submitter: self.batch_submitter.clone(),
            cursor: self.preparation_cursor,
            latest_observed_sphere_block: self.preparation_cursor.sphere_height,
            observed_sphere_block: self.observed_sphere_block.clone(),
            submitted_sphere_block: self.submitted_sphere_block.clone(),
        }
    }
}

impl<P: SphereSequencerProvider> BatchPreparer<P> {
    async fn process_available_blocks(
        &mut self,
        ready_tx: &mpsc::Sender<ReadyBatch>,
    ) -> Result<()> {
        // Batches may only cover blocks that survive a crash: a settled block this node later
        // rebuilds with another hash would leave L1 on a chain no replica holds.
        let latest_sphere_block = self.provider.last_durable_block_num_hash()?.number;
        let scan_from = self.latest_observed_sphere_block.saturating_add(1);
        if latest_sphere_block < scan_from {
            return Ok(());
        }

        self.process_block_range(scan_from, latest_sphere_block, ready_tx)
            .await?;
        self.latest_observed_sphere_block = latest_sphere_block;
        self.observed_sphere_block
            .store(latest_sphere_block, Ordering::Relaxed);
        self.metrics
            .latest_sphere_block_observed
            .set(latest_sphere_block as f64);
        self.metrics.sphere_to_l1_submission_lag_blocks.set(
            latest_sphere_block.saturating_sub(self.submitted_sphere_block.load(Ordering::Relaxed))
                as f64,
        );
        Ok(())
    }
}

impl<P: SphereSequencerProvider> SphereMonitor<P> {
    /// Rebuild the in-memory withdrawal store from authoritative chain state.
    ///
    /// The L1 portal only stores queue hashes, so the monitor reconstructs one head page from
    /// L1 + sphere-L2 events. Existing valid tail payloads are retained within the cache bound.
    async fn restore_pending_withdrawals_from_chain(&self) -> Result<()> {
        let pending = self.fetch_pending_withdrawals_from_chain().await?;
        self.replace_pending_withdrawals(pending);
        Ok(())
    }

    async fn fetch_pending_withdrawals_from_chain(&self) -> Result<WithdrawalPage> {
        match self
            .batch_submitter
            .fetch_pending_withdrawals(&self.provider, self.config.outbox_address)
            .await
        {
            Ok(pending) => Ok(pending),
            Err(err) => {
                self.metrics
                    .withdrawal_store_restore_failure_total
                    .increment(1);
                Err(err)
            }
        }
    }

    fn replace_pending_withdrawals(&self, pending: WithdrawalPage) {
        let restored_withdrawals = pending.batches.values().map(Vec::len).sum::<usize>();
        let page_head = pending.head;
        let tail = pending.tail;

        let mut store = self.withdrawal_store.lock();
        let previous_slots = store.batch_count();
        let evicted_tail_slots = store.replace_page(pending);
        let reconciled_slots = store.batch_count();
        drop(store);

        if reconciled_slots > 0 {
            info!(
                page_head,
                tail,
                previous_slots,
                reconciled_slots,
                restored_withdrawals,
                evicted_tail_slots,
                "Restored pending withdrawals from chain"
            );
            self.withdrawal_notify.notify_one();
        } else if previous_slots > 0 {
            info!(
                page_head,
                tail,
                previous_slots,
                "Cleared stale withdrawal cache after observing an empty portal queue"
            );
        }
    }

    /// Refill the bounded withdrawal cache after the processor reports a missing head slot.
    async fn refill_withdrawal_cache(&self) {
        self.metrics.withdrawal_store_refill_total.increment(1);
        if let Err(error) = self.restore_pending_withdrawals_from_chain().await {
            error!(%error, "Failed to refill the portal withdrawal head page");
        }
    }
}

impl<P: SphereSequencerProvider> BatchPreparer<P> {
    /// Process finalized batch boundaries in `[from, to]`.
    ///
    /// The builder records each batch boundary with one `BatchFinalized` event.
    /// The monitor must walk those boundaries one at a time so the L2 outbox
    /// index and L1 portal index advance in lockstep.
    #[instrument(skip(self, ready_tx), fields(from, to))]
    async fn process_block_range(
        &mut self,
        from: u64,
        to: u64,
        ready_tx: &mpsc::Sender<ReadyBatch>,
    ) -> Result<bool> {
        let block_count = to - from + 1;
        info!(from, to, block_count, "Processing sphere block range");

        let boundaries =
            fetch_finalized_batch_boundaries(&self.provider, self.config.outbox_address, from, to)
                .await?;
        if boundaries.is_empty() {
            info!(from, to, "No finalized batch boundaries ready to submit");
            return Ok(false);
        }

        info!(
            boundary_count = boundaries.len(),
            from,
            to,
            first_boundary = boundaries[0].block_number,
            last_boundary = boundaries[boundaries.len() - 1].block_number,
            "Preparing finalized Sphere batches"
        );

        for (idx, boundary) in boundaries.into_iter().enumerate() {
            let boundary_block = boundary.block_number;
            if boundary_block <= self.cursor.sphere_height {
                continue;
            }
            let range_start = self.cursor.sphere_height + 1;
            info!(
                batch = idx + 1,
                sphere_from = range_start,
                sphere_to = boundary_block,
                "Preparing finalized sphere batch"
            );

            // Reserve queue capacity before doing expensive work. This bounds speculative work to
            // one ready batch beyond the batch currently being submitted.
            let permit = ready_tx
                .reserve()
                .await
                .map_err(|_| eyre::eyre!("batch submission worker stopped"))?;
            let ready = self.process_finalized_batch(boundary).await?;
            self.cursor.advance(&ready.prepared.batch);
            permit.send(ready);
        }

        Ok(true)
    }

    /// Process one boundary-aligned finalized batch.
    async fn process_finalized_batch(
        &self,
        boundary: FinalizedBatchLog,
    ) -> std::result::Result<ReadyBatch, BatchSubmitError> {
        let from = self.cursor.sphere_height.saturating_add(1);
        let to = boundary.block_number;
        let finalized_batch =
            fetch_finalized_batch(&self.provider, self.config.outbox_address, &boundary).await?;
        let end_state = read_sphere_block_snapshot(&self.provider, self.config.inbox_address, to)?;

        if !finalized_batch.withdrawals.is_empty() {
            info!(
                from,
                to,
                count = finalized_batch.withdrawals.len(),
                withdrawal_queue_hash = %finalized_batch.finalized_hash,
                withdrawal_batch_index = finalized_batch.finalized_index,
                "Collected finalized withdrawals from sphere"
            );
        }

        let batch = BatchData {
            sphere_height: to,
            arc_block_number: end_state.arc_block_number,
            prev_block_hash: self.cursor.block_hash,
            next_block_hash: end_state.block_hash,
            prev_processed_deposit_hash: self.cursor.processed_deposit_hash,
            next_processed_deposit_hash: end_state.processed_deposit_hash,
            prev_deposit_number: self.cursor.processed_deposit_number,
            next_deposit_number: end_state.processed_deposit_number,
            prev_processed_token_count: self.cursor.processed_token_count,
            next_processed_token_count: end_state.processed_token_count,
            withdrawal_queue_hash: finalized_batch.finalized_hash,
            withdrawal_batch_index: finalized_batch.finalized_index,
        };

        loop {
            let prepared = self.batch_submitter.prepare_batch(batch.clone()).await?;
            match self
                .prepare_artifacts(prepared, finalized_batch.withdrawals.clone())
                .await
            {
                Err(BatchSubmitError::PreparedAnchorInvalid(error)) => {
                    warn!(
                        sphere_from = from,
                        sphere_to = to,
                        %error,
                        "Prepared batch anchor expired or changed; rebuilding preparation"
                    );
                }
                result => return result,
            }
        }
    }

    /// Prepare the settlement certificate.
    async fn prepare_artifacts(
        &self,
        prepared: PreparedBatch,
        withdrawals: Vec<abi::Withdrawal>,
    ) -> std::result::Result<ReadyBatch, BatchSubmitError> {
        let certificate = self
            .prepare_certificate(&prepared, VerifierMode::NoProof)
            .await?;
        Ok(ReadyBatch {
            prepared,
            verifier_mode: VerifierMode::NoProof,
            certificate,
            withdrawals,
        })
    }

    async fn prepare_certificate(
        &self,
        prepared: &PreparedBatch,
        verifier_mode: VerifierMode,
    ) -> Result<Option<SettlementCertificate>, BatchSubmitError> {
        match &self.config.settlements {
            Some(settlements) => settlements.prepare(prepared, verifier_mode).await.map(Some),
            None => Ok(None),
        }
    }
}

impl<P: SphereSequencerProvider> SphereMonitor<P> {
    /// Submit a prepared batch to the SpherePortal on L1 with exponential backoff retry.
    ///
    /// A portal mismatch or exhausted retries invalidates the pipeline so the monitor can restart
    /// from portal-confirmed state. The verifier mode and certificate stay fixed across
    /// retries.
    async fn submit_ready_batch(&mut self, ready: ReadyBatch) -> Result<()> {
        let ReadyBatch {
            prepared,
            verifier_mode,
            certificate,
            withdrawals,
        } = ready;
        let batch_data = &prepared.batch;
        let last_sphere_block = batch_data.sphere_height;
        let mut delay = INITIAL_RETRY_DELAY;

        for attempt in 1..=MAX_RETRIES {
            // A prior transaction may have landed even if its receipt timed out. Check the portal
            // before each attempt and rebuild the whole pipeline if its predecessor has changed.
            let portal_hash = match self.batch_submitter.read_portal_block_hash().await {
                Ok(portal_hash) => portal_hash,
                Err(error) => {
                    if attempt < MAX_RETRIES {
                        self.metrics.batch_submit_retry_total.increment(1);
                        warn!(
                            attempt,
                            max_retries = MAX_RETRIES,
                            delay_secs = delay.as_secs(),
                            %error,
                            "Failed reading portal state before batch submission, retrying"
                        );
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }
                    self.metrics.batch_submit_failure_total.increment(1);
                    error!(
                        %error,
                        last_sphere_block,
                        "Failed reading portal state before batch submission after {MAX_RETRIES} retries"
                    );
                    break;
                }
            };
            if portal_hash != batch_data.prev_block_hash {
                eyre::bail!(
                    "portal block hash {portal_hash} no longer matches predecessor {} for sphere \
                     batch {last_sphere_block}; invalidating prepared batch pipeline",
                    batch_data.prev_block_hash
                );
            }

            let submit_started = std::time::Instant::now();
            match self
                .batch_submitter
                .submit_batch(&prepared, certificate.as_ref(), verifier_mode)
                .await
            {
                Ok(event) => {
                    let portal_index = if event.withdrawalQueueIndex == NO_QUEUE_INDEX {
                        None
                    } else {
                        Some(event.withdrawalQueueIndex.try_into().map_err(|_| {
                            eyre::eyre!("withdrawal queue index overflow in BatchSubmitted")
                        })?)
                    };

                    self.metrics
                        .batch_submit_latency_seconds
                        .record(submit_started.elapsed().as_secs_f64());
                    let previous_sphere_block = self.submitted_sphere_block();
                    let blocks_in_batch = last_sphere_block - previous_sphere_block;
                    info!(
                        last_sphere_block,
                        blocks_in_batch,
                        arc_block_number = batch_data.arc_block_number,
                        withdrawal_batch_index = event.withdrawalBatchIndex,
                        withdrawal_queue_index = %event.withdrawalQueueIndex,
                        withdrawal_queue_hash = %batch_data.withdrawal_queue_hash,
                        "Batch successfully submitted to L1"
                    );
                    self.metrics.batch_submit_success_total.increment(1);
                    self.metrics
                        .batch_size_blocks
                        .record(blocks_in_batch as f64);
                    self.metrics
                        .withdrawals_per_batch
                        .record(withdrawals.len() as f64);

                    self.submitted_sphere_block
                        .store(last_sphere_block, Ordering::Relaxed);
                    self.metrics
                        .latest_sphere_block_submitted_to_l1
                        .set(last_sphere_block as f64);
                    self.update_submission_lag();

                    if let Some(portal_index) = portal_index {
                        if !withdrawals.is_empty() {
                            let count = withdrawals.len();
                            let mut store = self.withdrawal_store.lock();
                            if !store.add_batch(portal_index, withdrawals) {
                                debug!(
                                    portal_index,
                                    count,
                                    "Withdrawal cache full; dropped reconstructible far-tail payload"
                                );
                            }
                        }
                    } else if !batch_data.withdrawal_queue_hash.is_zero() || !withdrawals.is_empty()
                    {
                        warn!(
                            withdrawal_queue_hash = %batch_data.withdrawal_queue_hash,
                            withdrawal_count = withdrawals.len(),
                            "submitBatch emitted NO_QUEUE_INDEX for a batch that locally had withdrawals"
                        );
                    }

                    self.withdrawal_notify.notify_one();
                    return Ok(());
                }
                Err(BatchSubmitError::PortalAdvanced) => {
                    self.metrics
                        .batch_submit_latency_seconds
                        .record(submit_started.elapsed().as_secs_f64());
                    eyre::bail!(
                        "portal advanced while submitting sphere batch {last_sphere_block}; \
                         invalidating prepared batch pipeline"
                    );
                }
                Err(BatchSubmitError::PreparedAnchorInvalid(error)) => {
                    return Err(error.wrap_err(format!(
                        "prepared anchor invalid while submitting sphere batch {last_sphere_block}"
                    )));
                }
                Err(BatchSubmitError::Other(error)) => {
                    self.metrics
                        .batch_submit_latency_seconds
                        .record(submit_started.elapsed().as_secs_f64());

                    if attempt < MAX_RETRIES {
                        self.metrics.batch_submit_retry_total.increment(1);
                        warn!(
                            attempt,
                            max_retries = MAX_RETRIES,
                            delay_secs = delay.as_secs(),
                            %error,
                            "Batch submission failed, retrying"
                        );
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    } else {
                        self.metrics.batch_submit_failure_total.increment(1);
                        error!(
                            %error,
                            last_sphere_block,
                            arc_block_number = batch_data.arc_block_number,
                            prev_block_hash = %batch_data.prev_block_hash,
                            next_block_hash = %batch_data.next_block_hash,
                            "Batch submission failed after {MAX_RETRIES} retries"
                        );
                    }
                }
            }
        }

        Err(eyre::eyre!(
            "batch submission failed after {MAX_RETRIES} retries for sphere block {last_sphere_block}"
        ))
    }

    fn snapshot_at_or_genesis(
        provider: &P,
        inbox_address: Address,
        sphere_block_number: u64,
    ) -> Result<SphereBlockSnapshot> {
        if sphere_block_number == 0 {
            return Ok(SphereBlockSnapshot {
                arc_block_number: 0,
                processed_deposit_hash: B256::ZERO,
                processed_deposit_number: 0,
                processed_token_count: 0,
                block_hash: B256::ZERO,
            });
        }
        read_sphere_block_snapshot(provider, inbox_address, sphere_block_number)
    }

    fn update_submission_lag(&self) {
        let latest_observed_sphere_block = self.observed_sphere_block.load(Ordering::Relaxed);
        let submitted_sphere_block = self.submitted_sphere_block();
        self.metrics
            .sphere_to_l1_submission_lag_blocks
            .set(latest_observed_sphere_block.saturating_sub(submitted_sphere_block) as f64);
    }

    fn submitted_sphere_block(&self) -> u64 {
        self.submitted_sphere_block.load(Ordering::Relaxed)
    }
}

/// Spawn the sphere monitor as a background task.
///
/// The monitor consumes persisted Sphere block notifications and submits finalized batch
/// boundaries to the SpherePortal on Arc L1. Local state only advances on successful submission.
///
/// The `l1_provider` must already include the sequencer wallet for signing L1 transactions.
pub(crate) fn spawn_sphere_monitor<P>(
    config: SphereMonitorConfig,
    sphere_provider: P,
    l1_provider: DynProvider<Ethereum>,
    signer: PrivateKeySigner,
    shared_state: SphereMonitorSharedState,
    shutdown: sync::CancellationToken,
) -> tokio::task::JoinHandle<()>
where
    P: SphereSequencerProvider + PersistedBlockSubscriptions,
{
    let SphereMonitorSharedState {
        withdrawal_store,
        withdrawal_notify,
        repair_notify,
    } = shared_state;
    tokio::spawn(async move {
        loop {
            if shutdown.is_cancelled() {
                info!("Sphere monitor stopped before start");
                return;
            }
            let monitor = match SphereMonitor::new_with_provider(
                config.clone(),
                sphere_provider.clone(),
                l1_provider.clone(),
                Some(signer.clone()),
                withdrawal_store.clone(),
                withdrawal_notify.clone(),
                repair_notify.clone(),
            )
            .await
            {
                Ok(monitor) => monitor,
                Err(e) => {
                    error!(error = %e, "Sphere monitor failed to start, retrying in 5s");
                    if shutdown
                        .run_until_cancelled(tokio::time::sleep(RESTART_BACKOFF))
                        .await
                        .is_none()
                    {
                        info!("Sphere monitor stopped before start");
                        return;
                    }
                    continue;
                }
            };

            match monitor.run(&shutdown).await {
                Ok(()) => {
                    info!("Sphere monitor stopped");
                    return;
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Sphere monitor failed; rebuilding from the portal anchor in 5s"
                    );
                    if shutdown
                        .run_until_cancelled(tokio::time::sleep(RESTART_BACKOFF))
                        .await
                        .is_none()
                    {
                        info!("Sphere monitor stopped");
                        return;
                    }
                }
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Block, SpherePrimitives, SphereTxEnvelope};
    use alloy_consensus::{Header as ConsensusHeader, Signed, TxLegacy};
    use alloy_primitives::{Bytes, Log, Signature, U256};
    use alloy_provider::Provider as _;
    use alloy_sol_types::{SolEvent, SolValue};
    use alloy_transport::mock::Asserter;
    use reth_ethereum_primitives::{Receipt, TxType};
    use reth_provider::test_utils::MockEthProvider;
    fn mock_provider(asserter: Asserter) -> DynProvider<Ethereum> {
        alloy_provider::ProviderBuilder::new_with_network::<Ethereum>()
            .connect_mocked_client(asserter)
            .erased()
    }

    type TestSphereProvider = MockEthProvider<SpherePrimitives>;

    fn mock_sphere_provider(
        hash: B256,
        number: u64,
        processed_deposit_hash: B256,
    ) -> TestSphereProvider {
        let provider = TestSphereProvider::new();
        let event = abi::ArcAdvanced {
            arcBlockHash: B256::repeat_byte(0x55),
            arcBlockNumber: 123,
            depositsProcessed: U256::ZERO,
            newProcessedDepositQueueHash: processed_deposit_hash,
            lastProcessedDepositNumber: 0,
            lastProcessedEnabledTokenCount: 0,
        };
        let tx = SphereTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy::default(),
            Signature::test_signature(),
        ));
        let mut header = ConsensusHeader::default();
        header.number = number;
        provider.add_block(
            hash,
            Block {
                header,
                body: alloy_consensus::BlockBody {
                    transactions: vec![tx],
                    ..Default::default()
                },
            },
        );
        provider.add_receipts(
            number,
            vec![Receipt {
                tx_type: TxType::Legacy,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![Log {
                    address: Address::repeat_byte(0x33),
                    data: event.encode_log_data(),
                }],
            }],
        );
        provider
    }

    fn abi_encode_b256(value: B256) -> Bytes {
        value.into()
    }

    fn abi_encode_u64(value: u64) -> Bytes {
        value.abi_encode().into()
    }

    fn abi_encode_multicall(values: Vec<Bytes>) -> Bytes {
        (U256::ZERO, values).abi_encode_params().into()
    }

    fn test_monitor(
        l1: Asserter,
        sphere_provider: TestSphereProvider,
    ) -> SphereMonitor<TestSphereProvider> {
        let portal_address = Address::repeat_byte(0x11);
        let config = SphereMonitorConfig {
            outbox_address: Address::repeat_byte(0x22),
            inbox_address: Address::repeat_byte(0x33),
            poll_interval: Duration::from_secs(1),
            portal_address,
            batch_anchor_config: BatchAnchorConfig::default(),
            settlements: None,
        };
        let l1_provider = mock_provider(l1);
        let cursor = BatchCursor {
            sphere_height: 10,
            block_hash: B256::repeat_byte(0xbb),
            processed_deposit_hash: B256::repeat_byte(0xaa),
            processed_deposit_number: 0,
            processed_token_count: 0,
        };

        SphereMonitor {
            config,
            metrics: crate::metrics::SphereMonitorMetrics::default(),
            provider: sphere_provider,
            withdrawal_store: SharedWithdrawalStore::new(),
            batch_submitter: Arc::new(BatchSubmitter::new(portal_address, l1_provider)),
            withdrawal_notify: Arc::new(Notify::new()),
            repair_notify: Arc::new(Notify::new()),
            preparation_cursor: cursor,
            observed_sphere_block: Arc::new(AtomicU64::new(50)),
            submitted_sphere_block: Arc::new(AtomicU64::new(10)),
        }
    }

    fn prepared(batch: BatchData) -> PreparedBatch {
        PreparedBatch {
            anchor: crate::BatchAnchor::Direct {
                block_hash: B256::ZERO,
            },
            batch,
        }
    }

    fn ready_batch(batch: BatchData) -> ReadyBatch {
        ReadyBatch {
            prepared: prepared(batch),
            verifier_mode: VerifierMode::NoProof,
            certificate: None,
            withdrawals: Vec::new(),
        }
    }
    #[tokio::test]
    async fn new_returns_error_when_startup_l1_read_fails() {
        let l1 = Asserter::new();
        let portal_address = Address::repeat_byte(0x11);
        let config = SphereMonitorConfig {
            outbox_address: Address::repeat_byte(0x22),
            inbox_address: Address::repeat_byte(0x33),
            poll_interval: Duration::from_secs(1),
            portal_address,
            batch_anchor_config: BatchAnchorConfig::default(),
            settlements: None,
        };

        l1.push_failure_msg("boom");

        let err = match SphereMonitor::new_with_provider(
            config,
            TestSphereProvider::new(),
            mock_provider(l1.clone()),
            None,
            SharedWithdrawalStore::new(),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
        )
        .await
        {
            Ok(_) => panic!("sphere monitor startup should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains(
            "failed to resolve portal-confirmed sphere block during sphere monitor startup"
        ));
        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn refill_withdrawal_cache_does_not_resync_the_portal_anchor() {
        let l1 = Asserter::new();
        let portal_hash = B256::with_last_byte(7);
        let sphere = mock_sphere_provider(portal_hash, 42, B256::repeat_byte(0x33));

        l1.push_success(&abi_encode_multicall(vec![
            abi_encode_u64(7),
            abi_encode_u64(7),
        ]));

        let monitor = test_monitor(l1.clone(), sphere);
        let old_cursor = monitor.preparation_cursor;
        let old_last_submitted = monitor.submitted_sphere_block();
        monitor.withdrawal_store.lock().add_withdrawal(
            3,
            abi::Withdrawal {
                token: Address::repeat_byte(0x10),
                senderTag: B256::repeat_byte(0x11),
                to: Address::repeat_byte(0x12),
                amount: 100,
                memo: B256::ZERO,
                gasLimit: 0,
                fallbackNonce: 1,
                callbackData: Default::default(),
                encryptedSender: Default::default(),
            },
        );

        monitor.refill_withdrawal_cache().await;

        let store = monitor.withdrawal_store.lock();
        assert_eq!(store.batch_count(), 0);
        assert_eq!(monitor.preparation_cursor.block_hash, old_cursor.block_hash);
        assert_eq!(monitor.submitted_sphere_block(), old_last_submitted);
        assert_eq!(
            monitor.preparation_cursor.processed_deposit_hash,
            old_cursor.processed_deposit_hash
        );
        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn preflight_hash_mismatch_invalidates_pipeline() {
        let l1 = Asserter::new();
        let portal_hash = B256::with_last_byte(7);
        l1.push_success(&abi_encode_b256(portal_hash));

        let mut monitor = test_monitor(l1.clone(), TestSphereProvider::new());
        let old_cursor = monitor.preparation_cursor;
        let batch_data = BatchData {
            sphere_height: 20,
            arc_block_number: 123,
            prev_block_hash: B256::repeat_byte(0x99),
            next_block_hash: B256::repeat_byte(0x55),
            prev_processed_deposit_hash: B256::repeat_byte(0x77),
            next_processed_deposit_hash: B256::repeat_byte(0x66),
            prev_deposit_number: 0,
            next_deposit_number: 0,
            prev_processed_token_count: 0,
            next_processed_token_count: 0,
            withdrawal_queue_hash: B256::ZERO,
            withdrawal_batch_index: 8,
        };

        let error = monitor
            .submit_ready_batch(ready_batch(batch_data.clone()))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalidating prepared batch pipeline")
        );
        assert_eq!(monitor.submitted_sphere_block(), 10);
        assert_eq!(monitor.preparation_cursor.block_hash, old_cursor.block_hash);
        assert_eq!(
            monitor.preparation_cursor.processed_deposit_hash,
            old_cursor.processed_deposit_hash
        );
        assert_ne!(
            monitor.preparation_cursor.block_hash,
            batch_data.next_block_hash
        );
        assert_ne!(
            monitor.preparation_cursor.processed_deposit_hash,
            batch_data.next_processed_deposit_hash
        );
        assert!(l1.read_q().is_empty());
    }
}
