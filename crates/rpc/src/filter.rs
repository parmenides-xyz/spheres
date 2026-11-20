//! Privacy-enforced log filtering for the sphere's redacted RPC.

use alloy_consensus::TxReceipt;
use alloy_eips::eip4788::SYSTEM_ADDRESS;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::{Filter, FilterSet, Log, TransactionReceipt};
use alloy_sol_types::SolEvent;
use sphere_contracts::precompiles::NATIVE_FIAT_TOKEN_ADDRESS;

alloy_sol_types::sol!("../contracts/lib/forge-std/src/interfaces/IERC20.sol");

use crate::types::JsonRpcError;

/// `Transfer(address,address,uint256)`
pub const TRANSFER_TOPIC: B256 = IERC20::Transfer::SIGNATURE_HASH;

/// `Approval(address,address,uint256)`
pub const APPROVAL_TOPIC: B256 = IERC20::Approval::SIGNATURE_HASH;

pub const WHITELISTED_TOPICS: [B256; 2] = [TRANSFER_TOPIC, APPROVAL_TOPIC];
const CALLER_SCOPED_FILTER_ERROR: &str =
    "private log filter must include authenticated caller in topic1 or topic2";

pub fn is_caller_eligible(log: &Log, caller: &Address) -> bool {
    let topics = log.topics();
    let Some(topic0) = log.topic0() else {
        return false;
    };

    let caller_word = caller.into_word();

    if *topic0 == TRANSFER_TOPIC || *topic0 == APPROVAL_TOPIC {
        topics.get(1) == Some(&caller_word) || topics.get(2) == Some(&caller_word)
    } else {
        false
    }
}

/// Filters logs to only those the caller is allowed to see.
///
/// A log is included only when **both** of the following hold:
/// 1. Its topic0 is one of the [`WHITELISTED_TOPICS`].
/// 2. The `caller` is eligible per [`is_caller_eligible`].
pub fn is_log_visible(log: &Log, caller: &Address) -> bool {
    log.topic0().is_some_and(|t| WHITELISTED_TOPICS.contains(t)) && is_caller_eligible(log, caller)
}

/// Renumbers ordering fields on a sequence of logs so that
/// `(transactionHash, logIndex)` is stable and per-tx, without leaking
/// how many other logs preceded them.
///
/// `logIndex` restarts at `0` for each new tx and increments for each
/// subsequent log within that same tx.
/// `transactionIndex` is always zeroed to hide ordering within the block.
#[derive(Default)]
pub struct LogOrderingRedactor {
    current_tx: Option<B256>,
    next_index: u64,
}

impl LogOrderingRedactor {
    /// Redact the ordering fields of a single already-visible log.
    pub fn redact(&mut self, mut log: Log) -> Log {
        if self.current_tx != log.transaction_hash {
            self.current_tx = log.transaction_hash;
            self.next_index = 0;
        }
        log.transaction_index = Some(0);
        log.log_index = Some(self.next_index);
        self.next_index += 1;
        log
    }
}

/// Filters logs to only those the caller is allowed to see, renumbering the
/// `log_index` via [`LogOrderingRedactor`].
pub fn filter_logs(logs: Vec<Log>, caller: &Address) -> Vec<Log> {
    let mut redactor = LogOrderingRedactor::default();
    logs.into_iter()
        .filter(|log| is_log_visible(log, caller))
        .map(|log| redactor.redact(log))
        .collect()
}

/// Filters a receipt's logs for its sender and recomputes `logsBloom`.
pub fn filter_receipt_logs(mut receipt: TransactionReceipt) -> TransactionReceipt {
    let caller = receipt.from;
    receipt.transaction_index = Some(0);
    let inner = receipt.inner.as_receipt_with_bloom_mut().unwrap();
    inner.receipt.cumulative_gas_used = receipt.gas_used;
    let logs = core::mem::take(&mut inner.receipt.logs);
    inner.receipt.logs = filter_logs(logs, &caller);
    inner.logs_bloom = inner.receipt.bloom();
    receipt
}

/// Scopes a user-supplied filter to Arc USDC and native transfer logs.
pub fn scope_filter_addresses(filter: &mut Filter) -> Result<(), JsonRpcError> {
    let allowed_addresses = [NATIVE_FIAT_TOKEN_ADDRESS, SYSTEM_ADDRESS];
    let requested_addresses: Vec<Address> = filter.address.iter().copied().collect();

    if requested_addresses.is_empty() {
        filter.address = FilterSet::from(allowed_addresses.to_vec());
        return Ok(());
    }

    if requested_addresses
        .iter()
        .all(|address| allowed_addresses.contains(address))
    {
        Ok(())
    } else {
        Err(JsonRpcError::invalid_params("invalid filter address"))
    }
}

/// Scopes a user-supplied filter to only match whitelisted event topics.
///
/// Intersects the user's requested topic0 with [`WHITELISTED_TOPICS`].
/// If the user omitted topic0, restricts to the whitelisted set.
/// If the intersection is empty, sets topic0 to a dummy that will match nothing.
///
/// The post-filter in [`filter_logs`] remains the actual privacy enforcement;
/// this pre-filter reduces DB scan volume and timing side-channels.
pub fn scope_filter(filter: &mut Filter) {
    // --- Topic0 scoping ---
    let user_topic0: Vec<B256> = filter.topics[0].iter().copied().collect();

    let scoped_topic0: Vec<B256> = if user_topic0.is_empty() {
        // User didn't specify — restrict to whitelisted events
        WHITELISTED_TOPICS.to_vec()
    } else {
        // Intersect user's requested topics with whitelist
        user_topic0
            .into_iter()
            .filter(|t| WHITELISTED_TOPICS.contains(t))
            .collect()
    };

    if scoped_topic0.is_empty() {
        // No matching topics — use a dummy topic that will never match
        filter.topics[0] = FilterSet::from(B256::ZERO);
    } else {
        filter.topics[0] = FilterSet::from(scoped_topic0);
    }
}

/// Scopes a user-supplied filter to whitelisted event topics and requires the
/// authenticated caller to appear in an eligible indexed topic before backend
/// log retrieval.
pub fn scope_filter_for_caller(filter: &mut Filter, caller: &Address) -> Result<(), JsonRpcError> {
    scope_filter(filter);
    if filter.topics[0].len() == 1 && filter.topics[0].contains(&B256::ZERO) {
        return Ok(());
    }

    let caller_word = caller.into_word();
    if filter.topics[1].contains(&caller_word) {
        filter.topics[1] = FilterSet::from(caller_word);
        return Ok(());
    }
    if filter.topics[2].contains(&caller_word) {
        filter.topics[2] = FilterSet::from(caller_word);
        return Ok(());
    }

    Err(JsonRpcError::invalid_params(CALLER_SCOPED_FILTER_ERROR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, LogData, TxHash, keccak256};
    /// Build a test `Log` with the given emitting address and topics.
    fn make_log(emitter: Address, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy_primitives::Log {
                address: emitter,
                data: LogData::new_unchecked(topics, Bytes::new()),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        }
    }

    #[test]
    fn transfer_eligible_as_sender() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_eligible_as_receiver() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, other.into_word(), caller.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn transfer_rejected_when_not_participant() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let log = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, a.into_word(), b.into_word()],
        );
        assert!(!is_caller_eligible(&log, &caller));
    }

    // ---------------------------------------------------------------
    // is_caller_eligible — Approval
    // ---------------------------------------------------------------

    #[test]
    fn approval_eligible_as_owner() {
        let caller = Address::with_last_byte(1);
        let spender = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, caller.into_word(), spender.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn approval_eligible_as_spender() {
        let caller = Address::with_last_byte(1);
        let owner = Address::with_last_byte(2);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, owner.into_word(), caller.into_word()],
        );
        assert!(is_caller_eligible(&log, &caller));
    }

    #[test]
    fn approval_rejected_when_not_participant() {
        let caller = Address::with_last_byte(1);
        let a = Address::with_last_byte(2);
        let b = Address::with_last_byte(3);
        let log = make_log(
            Address::ZERO,
            vec![APPROVAL_TOPIC, a.into_word(), b.into_word()],
        );
        assert!(!is_caller_eligible(&log, &caller));
    }

    #[test]
    fn unknown_topic_rejected() {
        let caller = Address::with_last_byte(1);
        let unknown = B256::with_last_byte(0xff);
        let log = make_log(Address::ZERO, vec![unknown, caller.into_word()]);
        assert!(!is_caller_eligible(&log, &caller));
    }

    #[test]
    fn empty_topics_rejected() {
        let caller = Address::with_last_byte(1);
        let log = make_log(Address::ZERO, vec![]);
        assert!(!is_caller_eligible(&log, &caller));
    }
    fn make_receipt(from: Address, logs: Vec<Log>) -> TransactionReceipt {
        let receipt = alloy_consensus::Receipt {
            status: true.into(),
            cumulative_gas_used: 21_000,
            logs,
        };

        TransactionReceipt {
            inner: alloy_consensus::ReceiptEnvelope::Legacy(receipt.into()),
            transaction_hash: TxHash::with_last_byte(1),
            transaction_index: Some(0),
            block_hash: Some(B256::with_last_byte(2)),
            block_number: Some(1),
            gas_used: 21_000,
            effective_gas_price: 1,
            blob_gas_used: None,
            blob_gas_price: None,
            from,
            to: Some(Address::ZERO),
            contract_address: None,
        }
    }

    #[test]
    fn filter_receipt_logs_recomputes_logs_and_bloom() {
        let caller = Address::with_last_byte(1);
        let other = Address::with_last_byte(2);
        let third = Address::with_last_byte(3);
        let hidden_topic = keccak256(b"PolicyUpdated(address,uint256)");

        let visible = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, caller.into_word(), other.into_word()],
        );
        let hidden_transfer = make_log(
            Address::ZERO,
            vec![TRANSFER_TOPIC, other.into_word(), third.into_word()],
        );
        let hidden_event = make_log(Address::ZERO, vec![hidden_topic, caller.into_word()]);

        let filtered = filter_receipt_logs(make_receipt(
            caller,
            vec![
                visible.clone(),
                hidden_transfer.clone(),
                hidden_event.clone(),
            ],
        ));

        let mut expected_visible = visible;
        expected_visible.transaction_index = Some(0);
        expected_visible.log_index = Some(0);

        assert_eq!(
            filtered.inner.logs(),
            std::slice::from_ref(&expected_visible)
        );
        assert_eq!(filtered.transaction_index, Some(0));
        assert_eq!(filtered.inner.cumulative_gas_used(), filtered.gas_used);
        assert_eq!(
            filtered.inner.bloom(),
            alloy_primitives::logs_bloom(filtered.inner.logs().iter().map(|log| log.as_ref())),
        );
        assert_ne!(
            filtered.inner.bloom(),
            alloy_primitives::logs_bloom(
                [expected_visible, hidden_transfer, hidden_event]
                    .iter()
                    .map(|log| log.as_ref())
            ),
        );
    }
    #[test]
    fn scope_filter_addresses_scopes_omitted_address() {
        let mut filter = Filter::default();

        scope_filter_addresses(&mut filter).unwrap();

        assert!(filter.address.contains(&NATIVE_FIAT_TOKEN_ADDRESS));
        assert!(filter.address.contains(&SYSTEM_ADDRESS));
        assert_eq!(filter.address.len(), 2);
    }

    #[test]
    fn scope_filter_addresses_allows_enabled_addresses() {
        let token = NATIVE_FIAT_TOKEN_ADDRESS;
        for address in [token, SYSTEM_ADDRESS] {
            let mut filter = Filter {
                address: FilterSet::from(address),
                ..Default::default()
            };

            scope_filter_addresses(&mut filter).unwrap();

            assert_eq!(filter.address, FilterSet::from(address));
        }
    }

    #[test]
    fn scope_filter_addresses_rejects_non_sphere_token_address() {
        let token = NATIVE_FIAT_TOKEN_ADDRESS;
        let other = Address::with_last_byte(0xcc);
        let mut filter = Filter {
            address: FilterSet::from(vec![token, other]),
            ..Default::default()
        };

        let err = scope_filter_addresses(&mut filter).unwrap_err();

        assert_eq!(err.code, JsonRpcError::invalid_params("").code);
        assert_eq!(err.message, "invalid filter address");
    }
}
