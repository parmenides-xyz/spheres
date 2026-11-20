use alloy_consensus::BlockHeader;
use alloy_network::{Ethereum, ReceiptResponse, TransactionBuilder, TransactionResponse};
use alloy_primitives::{Address, B256, Bloom, Bytes, U64, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{
    Block, BlockId, BlockNumberOrTag, BlockTransactions, FeeHistory, Filter, FilterChanges,
    FilterId, TransactionRequest,
    state::{EvmOverrides, StateOverride},
};
use futures::StreamExt;
use reth_provider::CanonStateSubscriptions;
use reth_rpc::{EthFilter, eth::filter::EthFilterError};
use reth_rpc_builder::EthHandlers;
use reth_rpc_eth_api::{
    AsEthApiError, EthApiTypes, EthFilterApiServer, RpcConvert,
    helpers::{EthApiSpec, EthBlocks, EthCall, EthFees, EthState, EthTransactions, FullEthApi},
};
use reth_rpc_eth_types::{
    EthApiError,
    error::{RpcInvalidTransactionError, RpcPoolError},
    logs_utils,
};
use reth_storage_api::StateProviderFactory;
use sphere_contracts::{SPHERE_TOKEN_ADDRESS, SpherePortal};
use sphere_l1::ArcStateExt as _;
use sphere_rpc::{
    BoxWsSubscriptionFut,
    auth::AuthContext,
    types::{
        AuthorizationTokenInfoResponse, BoxFut, JsonRpcError, SphereInfoResponse, internal,
        raw_null, raw_zero, to_raw,
    },
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    sync::Mutex,
    time::{MissedTickBehavior, interval},
};
async fn sphere_tokens(
    portal_address: Address,
    l1_provider: &DynProvider<Ethereum>,
) -> Result<Vec<Address>, JsonRpcError> {
    if portal_address.is_zero() {
        return Ok(vec![SPHERE_TOKEN_ADDRESS]);
    }

    SpherePortal::new(portal_address, l1_provider)
        .enabled_tokens()
        .await
        .map_err(internal)
}

async fn sphere_sequencers(
    portal_address: Address,
    l1_provider: &DynProvider<Ethereum>,
) -> Result<Vec<Address>, JsonRpcError> {
    SpherePortal::new(portal_address, l1_provider)
        .sequencers()
        .await
        .map_err(internal)
}

/// Builds the Sphere metadata shared by the operator and redacted RPC surfaces.
///
/// The caller supplies the local Sphere's processed Arc block number; the
/// remaining dynamic fields are read directly from the SpherePortal on Arc L1.
async fn sphere_info(
    sphere_id: u32,
    chain_id: u64,
    portal_address: Address,
    arc_block_number: u64,
    l1_provider: &DynProvider<Ethereum>,
) -> Result<SphereInfoResponse, JsonRpcError> {
    let portal = SpherePortal::new(portal_address, l1_provider);
    let (sphere_tokens, sequencers, is_access_enforced, is_gateway_open) = tokio::try_join!(
        sphere_tokens(portal_address, l1_provider),
        sphere_sequencers(portal_address, l1_provider),
        async {
            if portal_address.is_zero() {
                Ok(false)
            } else {
                portal.isAccessEnforced().call().await.map_err(internal)
            }
        },
        async {
            if portal_address.is_zero() {
                Ok(true)
            } else {
                portal.isGatewayOpen().call().await.map_err(internal)
            }
        },
    )?;

    Ok(SphereInfoResponse {
        sphere_id: U64::from(sphere_id),
        is_access_enforced,
        is_gateway_open,
        sphere_tokens,
        sequencers,
        chain_id: U64::from(chain_id),
        arc_block_number: U64::from(arc_block_number),
    })
}

/// Reads the encryption key active at the current Arc L1 head.
async fn encryption_key(
    portal_address: Address,
    l1_provider: &DynProvider<Ethereum>,
) -> Result<SpherePortal::encryptionKeyAtBlockReturn, JsonRpcError> {
    let block_number = l1_provider.get_block_number().await.map_err(internal)?;
    SpherePortal::new(portal_address, l1_provider)
        .encryptionKeyAtBlock(block_number)
        .block(BlockId::number(block_number))
        .call()
        .await
        .map_err(internal)
}

type RpcBlock = Block<
    alloy_rpc_types_eth::Transaction<alloy_consensus::TxEnvelope>,
    alloy_rpc_types_eth::Header,
>;
const FILTER_OWNER_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
fn filter_not_found_error() -> JsonRpcError {
    JsonRpcError::invalid_params("filter not found")
}

fn map_eth_filter_error(err: EthFilterError) -> JsonRpcError {
    match err {
        EthFilterError::FilterNotFound(_) => filter_not_found_error(),
        other => internal(other),
    }
}

fn map_send_raw_transaction_error(err: impl AsEthApiError + std::fmt::Display) -> JsonRpcError {
    if let Some(EthApiError::PoolError(RpcPoolError::Invalid(
        RpcInvalidTransactionError::InsufficientFunds { .. },
    ))) = err.as_err()
    {
        return JsonRpcError::internal("insufficient funds for gas * price + value");
    }
    internal(err)
}

fn stale_filter_owner_ids(
    owner_ids: impl IntoIterator<Item = FilterId>,
    active_ids: &HashSet<FilterId>,
) -> Vec<FilterId> {
    owner_ids
        .into_iter()
        .filter(|id| !active_ids.contains(id))
        .collect()
}

async fn prune_filter_owners<Api: EthApiTypes + 'static>(
    filter: &EthFilter<Api>,
    owners: &Mutex<HashMap<FilterId, Address>>,
) {
    let owner_ids = {
        let owners = owners.lock().await;
        owners.keys().cloned().collect::<Vec<_>>()
    };
    if owner_ids.is_empty() {
        return;
    }

    let active_ids = filter
        .active_filters()
        .ids()
        .await
        .into_iter()
        .collect::<HashSet<_>>();
    let stale_ids = stale_filter_owner_ids(owner_ids, &active_ids);
    if stale_ids.is_empty() {
        return;
    }

    let mut owners = owners.lock().await;
    for id in stale_ids {
        owners.remove(&id);
    }
}

/// [`SphereRpcApi`] implementation backed by reth's [`EthHandlers`].
///
/// This is the privacy enforcement layer for the sphere's JSON-RPC surface.
/// Only methods explicitly routed through [`SphereRpcApi`] are reachable —
/// everything else is rejected by the dispatcher's typed method registry,
/// so this struct effectively acts as an **enforced allowlist**
/// of Ethereum JSON-RPC endpoints.
///
/// For every allowed endpoint it applies typed privacy checks *before*
/// serializing to JSON:
///
/// - **Block redaction** — zeroing `logsBloom` and clearing transaction
///   lists on the redacted RPC.
/// - **Sender-scoped access** — returning `null` for transactions and
///   receipts not owned by the authenticated caller.
/// - **`from`-enforcement** — `eth_call` / `eth_estimateGas` may only
///   simulate from the authenticated account (`-32004` on mismatch,
///   auto-set when omitted); state overrides are rejected (`-32602`).
/// - **Sender verification** — `eth_sendRawTransaction` checks that the
///   recovered transaction sender matches the authenticated account
///   (`-32003` on mismatch).
pub struct SphereRpc<Api: EthApiTypes> {
    eth: EthHandlers<Api>,
    config: sphere_rpc::RedactedRpcConfig,
    l1_provider: DynProvider<Ethereum>,
    /// Maps filter IDs to the authenticated account that created them.
    /// The reth filter registry remains the source of truth for filter liveness.
    filter_owners: Arc<Mutex<HashMap<FilterId, Address>>>,
}

impl<Api: EthApiTypes + 'static> SphereRpc<Api> {
    /// Wrap reth's [`EthHandlers`] (api + filter + pubsub) and an L1 provider.
    pub fn new(
        eth: EthHandlers<Api>,
        config: sphere_rpc::RedactedRpcConfig,
        l1_provider: DynProvider<Ethereum>,
    ) -> Self {
        let rpc = Self {
            eth,
            config,
            l1_provider,
            filter_owners: Arc::new(Mutex::new(HashMap::new())),
        };
        rpc.spawn_filter_owner_pruner();
        rpc
    }

    /// Returns a reference to the inner [`EthFilter`] handler.
    pub fn filter(&self) -> &EthFilter<Api> {
        &self.eth.filter
    }

    async fn filter_is_active(&self, id: &FilterId) -> bool {
        self.filter().active_filters().contains(id).await
    }

    fn spawn_filter_owner_pruner(&self)
    where
        Api: Send + Sync + 'static,
    {
        let filter = self.filter().clone();
        let owners: Weak<Mutex<HashMap<FilterId, Address>>> = Arc::downgrade(&self.filter_owners);
        tokio::spawn(async move {
            let mut prune_interval = interval(FILTER_OWNER_PRUNE_INTERVAL);
            prune_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                prune_interval.tick().await;

                let Some(owners) = owners.upgrade() else {
                    break;
                };

                prune_filter_owners(&filter, &owners).await;
            }
        });
    }

    /// Verify that the filter belongs to the authenticated caller.
    ///
    /// Returns `Ok(())` if the caller owns the filter or is the sequencer.
    /// Returns an error indistinguishable from "filter not found" to avoid
    /// leaking filter existence to non-owners.
    async fn ensure_filter_owner(
        &self,
        id: &FilterId,
        auth: &AuthContext,
    ) -> Result<(), JsonRpcError> {
        let owner_matches = {
            let owners = self.filter_owners.lock().await;
            matches!(owners.get(id), Some(owner) if *owner == auth.caller)
        };
        if !owner_matches {
            return Err(filter_not_found_error());
        }
        if self.filter_is_active(id).await {
            Ok(())
        } else {
            self.filter_owners.lock().await.remove(id);
            Err(filter_not_found_error())
        }
    }

    fn enforce_authorized(
        &self,
        request: &mut TransactionRequest,
        auth: &AuthContext,
    ) -> Result<(), JsonRpcError> {
        sphere_rpc::policy::enforce_authorized(request, auth)
    }
}

impl<Api> SphereRpc<Api>
where
    Api: FullEthApi + EthApiTypes<NetworkTypes = Ethereum> + Send + Sync + 'static,
{
    fn block_by_id(&self, id: BlockId) -> BoxFut<'_> {
        Box::pin(async move {
            let block = EthBlocks::rpc_block(&self.eth.api, id, false)
                .await
                .map_err(internal)?;

            let Some(mut block) = block else {
                return Ok(raw_null());
            };

            redact_block(&mut block);

            to_raw(&block)
        })
    }
}

impl<Api> sphere_rpc::SphereRpcApi for SphereRpc<Api>
where
    Api: FullEthApi + EthApiTypes<NetworkTypes = Ethereum> + Send + Sync + 'static,
{
    fn block_number(&self) -> BoxFut<'_> {
        Box::pin(async move {
            let info = EthApiSpec::chain_info(&self.eth.api).map_err(internal)?;
            to_raw(&U256::from(info.best_number))
        })
    }

    fn chain_id(&self) -> BoxFut<'_> {
        Box::pin(async move {
            let chain_id = EthApiSpec::chain_id(&self.eth.api);
            to_raw(&Some(chain_id))
        })
    }

    fn net_version(&self) -> BoxFut<'_> {
        Box::pin(async move {
            let chain_id = EthApiSpec::chain_id(&self.eth.api);
            to_raw(&chain_id.to_string())
        })
    }

    fn client_version(&self) -> BoxFut<'_> {
        Box::pin(async { to_raw(&crate::version::client_version()) })
    }

    fn syncing(&self) -> BoxFut<'_> {
        Box::pin(async move {
            let status = EthApiSpec::sync_status(&self.eth.api).map_err(internal)?;
            to_raw(&status)
        })
    }

    fn coinbase(&self) -> BoxFut<'_> {
        Box::pin(async move {
            let header = EthBlocks::rpc_block_header(&self.eth.api, BlockId::latest())
                .await
                .map_err(internal)?
                .ok_or_else(|| JsonRpcError::internal("latest block not found"))?;
            to_raw(&header.beneficiary())
        })
    }

    fn gas_price(&self) -> BoxFut<'_> {
        Box::pin(async move { to_raw(&U256::ZERO) })
    }

    fn max_priority_fee_per_gas(&self) -> BoxFut<'_> {
        Box::pin(async move { to_raw(&U256::ZERO) })
    }

    fn fee_history(
        &self,
        block_count: u64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            let mut history =
                EthFees::fee_history(&self.eth.api, block_count, newest_block, reward_percentiles)
                    .await
                    .map_err(internal)?;
            // Redact gas fields (like `gas_used_ratio`) that can be used to guess tx counts
            redact_fee_history(&mut history);
            to_raw(&history)
        })
    }

    fn get_balance(
        &self,
        address: Address,
        block: Option<BlockId>,
        auth: AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            // Silent dummy: non-caller addresses get "0x0" to avoid leaking account existence.
            if address != auth.caller {
                return Ok(raw_zero());
            }
            let balance = EthState::balance(&self.eth.api, address, block)
                .await
                .map_err(internal)?;
            to_raw(&balance)
        })
    }

    fn get_transaction_count(
        &self,
        address: Address,
        block: Option<BlockId>,
        auth: AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            // Silent dummy: non-caller addresses get "0x0" to avoid leaking account existence.
            if address != auth.caller {
                return Ok(raw_zero());
            }
            let count = EthState::transaction_count(&self.eth.api, address, block)
                .await
                .map_err(internal)?;
            to_raw(&count)
        })
    }

    fn block_by_number(
        &self,
        number: BlockNumberOrTag,
        _full: bool,
        _auth: AuthContext,
    ) -> BoxFut<'_> {
        self.block_by_id(number.into())
    }

    fn block_by_hash(&self, hash: B256, _full: bool, _auth: AuthContext) -> BoxFut<'_> {
        self.block_by_id(hash.into())
    }

    fn transaction_by_hash(&self, hash: B256, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            let tx = EthTransactions::transaction_by_hash(&self.eth.api, hash)
                .await
                .map_err(internal)?
                .map(|src| src.into_transaction(self.eth.api.converter()))
                .transpose()
                .map_err(internal)?;

            let Some(mut tx) = tx else {
                return Ok(raw_null());
            };

            if tx.from() != auth.caller {
                return Ok(raw_null());
            }

            // transaction_index leaks how many txns were in this block, so redact
            tx.transaction_index = Some(0);

            to_raw(&tx)
        })
    }

    fn transaction_receipt(&self, hash: B256, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            let receipt = EthTransactions::transaction_receipt(&self.eth.api, hash)
                .await
                .map_err(internal)?;

            let Some(mut receipt) = receipt else {
                return Ok(raw_null());
            };

            if receipt.from() != auth.caller {
                return Ok(raw_null());
            }

            receipt = sphere_rpc::filter::filter_receipt_logs(receipt);

            to_raw(&receipt)
        })
    }

    fn call(
        &self,
        mut request: TransactionRequest,
        block: Option<BlockId>,
        state_override: Option<StateOverride>,
        auth: AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            if state_override.is_some() {
                return Err(JsonRpcError::invalid_params("state overrides not allowed"));
            }

            self.enforce_authorized(&mut request, &auth)?;

            let result = EthCall::call(
                &self.eth.api,
                request,
                block,
                EvmOverrides::state(state_override),
            )
            .await
            .map_err(internal)?;
            to_raw(&result)
        })
    }

    fn estimate_gas(
        &self,
        mut request: TransactionRequest,
        block: Option<BlockId>,
        state_override: Option<StateOverride>,
        auth: AuthContext,
    ) -> BoxFut<'_> {
        Box::pin(async move {
            if state_override.is_some() {
                return Err(JsonRpcError::invalid_params("state overrides not allowed"));
            }

            self.enforce_authorized(&mut request, &auth)?;

            let result = EthCall::estimate_gas_at(
                &self.eth.api,
                request,
                block.unwrap_or_default(),
                state_override,
            )
            .await
            .map_err(internal)?;
            to_raw(&result)
        })
    }

    fn send_raw_transaction(&self, data: Bytes, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::policy::verify_raw_tx_sender(&data, &auth)?;

            let hash = EthTransactions::send_raw_transaction(&self.eth.api, data)
                .await
                .map_err(map_send_raw_transaction_error)?;
            to_raw(&hash)
        })
    }

    fn send_raw_transaction_sync(&self, data: Bytes, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::policy::verify_raw_tx_sender(&data, &auth)?;

            let mut receipt = EthTransactions::send_raw_transaction_sync(&self.eth.api, data)
                .await
                .map_err(map_send_raw_transaction_error)?;

            receipt = sphere_rpc::filter::filter_receipt_logs(receipt);

            to_raw(&receipt)
        })
    }

    fn fill_transaction(&self, mut request: TransactionRequest, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            self.enforce_authorized(&mut request, &auth)?;

            // Prefill the users request so the `fill_transaction` doesnt leak dynamic fee estimates via
            // missing fee fields.
            apply_public_fee_policy(&mut request);

            let result = EthTransactions::fill_transaction(&self.eth.api, request)
                .await
                .map_err(internal)?;
            to_raw(&result)
        })
    }

    fn get_logs(&self, mut filter: Filter, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::filter::scope_filter_addresses(&mut filter)?;
            sphere_rpc::filter::scope_filter_for_caller(&mut filter, &auth.caller)?;
            let logs = EthFilterApiServer::logs(&self.eth.filter, filter)
                .await
                .map_err(internal)?;
            let filtered = sphere_rpc::filter::filter_logs(logs, &auth.caller);
            to_raw(&filtered)
        })
    }

    fn new_filter(&self, mut filter: Filter, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            sphere_rpc::filter::scope_filter_addresses(&mut filter)?;
            sphere_rpc::filter::scope_filter_for_caller(&mut filter, &auth.caller)?;
            let id = EthFilterApiServer::new_filter(&self.eth.filter, filter)
                .await
                .map_err(internal)?;
            self.filter_owners
                .lock()
                .await
                .insert(id.clone(), auth.caller);
            to_raw(&id)
        })
    }

    fn get_filter_logs(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            self.ensure_filter_owner(&id, &auth).await?;

            let logs = self
                .filter()
                .filter_logs(id)
                .await
                .map_err(map_eth_filter_error)?;

            let filtered = sphere_rpc::filter::filter_logs(logs, &auth.caller);
            to_raw(&filtered)
        })
    }

    fn get_filter_changes(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            self.ensure_filter_owner(&id, &auth).await?;

            let changes = self
                .filter()
                .filter_changes(id)
                .await
                .map_err(map_eth_filter_error)?;

            match changes {
                FilterChanges::Logs(logs) => {
                    let filtered = sphere_rpc::filter::filter_logs(logs, &auth.caller);
                    to_raw(&FilterChanges::<
                        alloy_rpc_types_eth::Transaction<alloy_consensus::TxEnvelope>,
                    >::Logs(filtered))
                }
                FilterChanges::Hashes(hashes) => to_raw(&FilterChanges::<
                    alloy_rpc_types_eth::Transaction<alloy_consensus::TxEnvelope>,
                >::Hashes(hashes)),
                // Pending transaction filters are disabled — return empty if one somehow exists
                FilterChanges::Transactions(_) => {
                    to_raw(
                        &FilterChanges::<
                            alloy_rpc_types_eth::Transaction<alloy_consensus::TxEnvelope>,
                        >::Empty,
                    )
                }
                FilterChanges::Empty => {
                    to_raw(
                        &FilterChanges::<
                            alloy_rpc_types_eth::Transaction<alloy_consensus::TxEnvelope>,
                        >::Empty,
                    )
                }
            }
        })
    }

    fn new_block_filter(&self, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            let id = EthFilterApiServer::new_block_filter(&self.eth.filter)
                .await
                .map_err(internal)?;
            self.filter_owners
                .lock()
                .await
                .insert(id.clone(), auth.caller);
            to_raw(&id)
        })
    }

    fn uninstall_filter(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            self.ensure_filter_owner(&id, &auth).await?;

            let result = EthFilterApiServer::uninstall_filter(&self.eth.filter, id.clone())
                .await
                .map_err(internal)?;

            if result || !self.filter_is_active(&id).await {
                self.filter_owners.lock().await.remove(&id);
            }

            to_raw(&result)
        })
    }

    fn ws_subscribe_new_heads(&self, _auth: AuthContext) -> BoxWsSubscriptionFut<'_> {
        Box::pin(async move {
            let api = self.eth.api.clone();
            let provider = self.eth.api.provider().clone();
            let stream = provider
                .canonical_state_stream()
                .flat_map(move |new_chain| {
                    let api = api.clone();
                    let headers = new_chain
                        .committed()
                        .blocks_iter()
                        .filter_map(move |block| {
                            match api
                                .converter()
                                .convert_header(block.clone_sealed_header(), block.rlp_length())
                            {
                                Ok(header) => Some(header),
                                Err(err) => {
                                    tracing::error!(
                                        target: "rpc",
                                        %err,
                                        "Failed to convert header"
                                    );
                                    None
                                }
                            }
                        })
                        .collect::<Vec<_>>();
                    futures::stream::iter(headers)
                })
                .map(move |mut header| {
                    redact_header(&mut header);
                    to_raw(&header)
                });
            let stream: sphere_rpc::WsSubscriptionStream = Box::pin(stream);
            Ok(stream)
        })
    }

    fn ws_subscribe_logs(&self, mut filter: Filter, auth: AuthContext) -> BoxWsSubscriptionFut<'_> {
        Box::pin(async move {
            let provider = self.eth.api.provider().clone();
            let caller = auth.caller;

            sphere_rpc::filter::scope_filter_addresses(&mut filter)?;
            sphere_rpc::filter::scope_filter_for_caller(&mut filter, &caller)?;

            let stream = provider
                .canonical_state_stream()
                .map(move |canon_state| canon_state.block_receipts())
                .flat_map(futures::stream::iter)
                .flat_map(move |(block_receipts, removed)| {
                    let all_logs = logs_utils::matching_block_logs_with_tx_hashes(
                        &filter,
                        block_receipts.block,
                        block_receipts.timestamp,
                        block_receipts
                            .tx_receipts
                            .iter()
                            .map(|(tx, receipt)| (*tx, receipt)),
                        removed,
                    );
                    futures::stream::iter(all_logs)
                });

            // Renumber `log_index` per-transaction so a log seen live over the
            // subscription carries the same `(transactionHash, logIndex)` it would
            // via `eth_getLogs`/`eth_getTransactionReceipt`.
            // Logs arrive in block order grouped by tx, which is what `LogOrderingRedactor` needs.
            let mut log_redactor = sphere_rpc::filter::LogOrderingRedactor::default();
            let stream = stream.filter_map(move |log| {
                std::future::ready(
                    sphere_rpc::filter::is_log_visible(&log, &caller)
                        .then(|| to_raw(&log_redactor.redact(log))),
                )
            });
            let stream: sphere_rpc::WsSubscriptionStream = Box::pin(stream);
            Ok(stream)
        })
    }

    fn sphere_get_authorization_token_info(&self, auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            to_raw(&AuthorizationTokenInfoResponse {
                account: auth.caller,
                expires_at: U64::from(auth.expires_at),
            })
        })
    }

    fn sphere_get_sphere_info(&self, _auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            let arc_block_number = self
                .eth
                .api
                .provider()
                .latest()
                .map_err(internal)?
                .arc_block_number()
                .map_err(internal)?;
            let info = sphere_info(
                self.config.sphere_id,
                self.config.chain_id,
                self.config.sphere_portal,
                arc_block_number,
                &self.l1_provider,
            )
            .await?;
            to_raw(&info)
        })
    }

    fn sphere_get_encryption_key(&self, _auth: AuthContext) -> BoxFut<'_> {
        Box::pin(async move {
            let key = encryption_key(self.config.sphere_portal, &self.l1_provider).await?;
            to_raw(&key)
        })
    }
}
/// Clear RPC header fields that reveal private execution state from the header
fn redact_header(header: &mut alloy_rpc_types_eth::Header) {
    header.size = header.size.map(|_| U256::ZERO);
    let inner = &mut header.inner;
    inner.gas_used = 0;
    inner.state_root = B256::ZERO;
    inner.transactions_root = B256::ZERO;
    inner.receipts_root = B256::ZERO;
    inner.logs_bloom = Bloom::ZERO;
    inner.extra_data = Bytes::new();
    inner.blob_gas_used = inner.blob_gas_used.map(|_| 0);
    inner.excess_blob_gas = inner.excess_blob_gas.map(|_| 0);
    inner.withdrawals_root = inner.withdrawals_root.map(|_| B256::ZERO);
}

/// Clear gas related fields that leak the size (and therefore tx counts)
fn redact_fee_history(history: &mut FeeHistory) {
    history.base_fee_per_gas.fill(0);
    history.gas_used_ratio.fill(0.0);
    history.base_fee_per_blob_gas.fill(0);
    history.blob_gas_used_ratio.fill(0.0);
    if let Some(rewards) = &mut history.reward {
        for block_rewards in rewards {
            block_rewards.fill(0);
        }
    }
}

/// Prefill missing transaction fee fields with public, deterministic values before calling reth's
/// transaction filler, so `eth_fillTransaction` does not expose dynamic fee estimates derived from
/// private sphere activity.
fn apply_public_fee_policy(request: &mut TransactionRequest) {
    if request.has_eip4844_fields() && request.max_fee_per_blob_gas.is_none() {
        request.max_fee_per_blob_gas = Some(0);
    }

    if request.gas_price.is_some() {
        return;
    }

    if matches!(request.transaction_type, Some(0 | 1)) {
        request.set_gas_price(0);
        return;
    }

    let priority_fee = request.max_priority_fee_per_gas.unwrap_or(0);
    if request.max_priority_fee_per_gas.is_none() {
        request.set_max_priority_fee_per_gas(0);
    }
    if request.max_fee_per_gas.is_none() {
        request.set_max_fee_per_gas(priority_fee);
    }
}

/// Strip privacy-sensitive fields from a block returned by the redacted RPC.
fn redact_block(block: &mut RpcBlock) {
    redact_header(&mut block.header);
    block.transactions = BlockTransactions::Hashes(Vec::new());
    block.withdrawals = block.withdrawals.take().map(|_| Default::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_header_clears_activity_metadata() {
        let mut header = alloy_rpc_types_eth::Header {
            hash: B256::with_last_byte(7),
            inner: alloy_consensus::Header {
                gas_used: 123,
                state_root: B256::with_last_byte(1),
                transactions_root: B256::with_last_byte(2),
                receipts_root: B256::with_last_byte(3),
                extra_data: Bytes::from_static(b"private"),
                blob_gas_used: Some(4),
                excess_blob_gas: Some(5),
                withdrawals_root: Some(B256::with_last_byte(6)),
                ..Default::default()
            },
            size: Some(U256::from(8)),
            ..Default::default()
        };

        redact_header(&mut header);

        let inner = &header.inner;
        assert_eq!(header.hash, B256::with_last_byte(7));
        assert_eq!(header.size, Some(U256::ZERO));
        assert_eq!(inner.gas_used, 0);
        assert_eq!(inner.state_root, B256::ZERO);
        assert_eq!(inner.transactions_root, B256::ZERO);
        assert_eq!(inner.receipts_root, B256::ZERO);
        assert_eq!(inner.logs_bloom, Bloom::ZERO);
        assert!(inner.extra_data.is_empty());
        assert_eq!(inner.blob_gas_used, Some(0));
        assert_eq!(inner.excess_blob_gas, Some(0));
        assert_eq!(inner.withdrawals_root, Some(B256::ZERO));
    }

    #[test]
    fn stale_filter_owner_ids_removes_only_inactive_entries() {
        let active_ids = HashSet::from([
            FilterId::Str("0xactive".to_string()),
            FilterId::Str("0xkeep".to_string()),
        ]);
        let owner_ids = vec![
            FilterId::Str("0xactive".to_string()),
            FilterId::Str("0xstale".to_string()),
            FilterId::Str("0xkeep".to_string()),
        ];

        let stale_ids = stale_filter_owner_ids(owner_ids, &active_ids);

        assert_eq!(stale_ids, vec![FilterId::Str("0xstale".to_string())]);
    }

    #[test]
    fn stale_filter_owner_ids_is_noop_for_empty_owner_set() {
        let stale_ids = stale_filter_owner_ids(Vec::new(), &HashSet::new());

        assert!(stale_ids.is_empty());
    }
}
