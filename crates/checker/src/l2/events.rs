//! Receipt-local authentication and normalization of L2 protocol events.

use std::collections::BTreeSet;

use alloy_consensus::{TxReceipt, transaction::TxHashRef};
use alloy_primitives::{Address, B256, Log, U256};
use alloy_sol_types::SolEvent;
use sphere_contracts::spheres::{SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS, SPHERE_TOKEN_ADDRESS};
use sphere_contracts::spheres::{ISphereInbox, ISphereOutbox};
use sphere_contracts::spheres::SpherePortal;

use crate::{NativeFiatTokenV2_2, decode_event};

/// Exact Arc/L1 block imported by `ArcAdvanced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct L1Anchor {
    pub(super) arc_block_hash: B256,
    pub(super) arc_block_number: u64,
}

impl L1Anchor {
    pub(crate) fn block_hash(&self) -> B256 {
        self.arc_block_hash
    }

    pub(crate) fn block_number(&self) -> u64 {
        self.arc_block_number
    }
}

/// One canonical ERC-20 ownership movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenTransfer {
    pub(crate) token: Address,
    pub(crate) from: Address,
    pub(crate) to: Address,
    pub(crate) amount: U256,
}

/// Result of executing one imported deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepositResult {
    Processed { recipient: Address },
    Failed,
}

/// Result of executing one imported withdrawal bounce-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalBounceBackStatus {
    Processed,
    Pending,
}

/// Authenticated origin of one Sphere withdrawal request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalOrigin {
    User { sender: Address, sender_tag: B256 },
    DepositBounceBack,
}

/// Semantic bridge activity authenticated from one Sphere receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum L2BridgeAction {
    Deposit {
        token: Address,
        amount: U256,
        result: DepositResult,
    },
    WithdrawalBounceBack {
        recipient: Address,
        token: Address,
        amount: U256,
        status: WithdrawalBounceBackStatus,
    },
    RefundClaimed {
        recipient: Address,
        token: Address,
        amount: U256,
    },
    WithdrawalRequested {
        withdrawal_index: u64,
        origin: WithdrawalOrigin,
        token: Address,
        principal: U256,
        fee: U256,
    },
}

/// Decoded receipt event retained until receipt authentication completes.
#[derive(Debug, Clone, Copy)]
enum ReceiptEvent {
    Anchor(L1Anchor),
    Action(L2BridgeAction),
    Transfer(TokenTransfer),
    TokenBurn {
        token: Address,
        from: Address,
        amount: U256,
    },
}

impl ReceiptEvent {
    /// Return whether this event burns tokens or moves them to the zero address.
    fn reduces_supply(&self) -> bool {
        match self {
            Self::TokenBurn { .. } => true,
            Self::Transfer(transfer) => transfer.to.is_zero(),
            Self::Anchor(_) | Self::Action(_) => false,
        }
    }
}

/// Reconcile Inbox mints with their outcome in one receipt.
fn authenticate_receipt_mints(
    transaction_hash: B256,
    receipt: &[ReceiptEvent],
) -> eyre::Result<()> {
    let mut index = 0;

    while let Some(event) = receipt.get(index) {
        let Some(observed) = Mint::from_transfer(event) else {
            if Mint::from_outcome(event).is_some() {
                eyre::bail!(
                    "transaction {} has an Inbox outcome without its mint",
                    transaction_hash,
                );
            }
            index += 1;
            continue;
        };

        index += 1;
        if receipt
            .get(index)
            .is_some_and(|event| observed.matches_forward(event))
        {
            index += 1;
        }

        let Some(expected) = receipt.get(index).and_then(Mint::from_outcome) else {
            eyre::bail!(
                "transaction {} has an unexplained mint of {} {} to {}",
                transaction_hash,
                observed.amount,
                observed.token,
                observed.recipient,
            );
        };

        eyre::ensure!(
            observed == expected,
            "transaction {} mint {:?} does not match Inbox outcome {:?}",
            transaction_hash,
            observed,
            expected,
        );
        index += 1;
    }
    Ok(())
}

/// ERC-20 mint expected from one successful Inbox action.
#[derive(Debug, PartialEq, Eq)]
struct Mint {
    token: Address,
    recipient: Address,
    amount: U256,
}

impl Mint {
    /// Decode a zero-address ERC-20 transfer as a mint.
    fn from_transfer(event: &ReceiptEvent) -> Option<Self> {
        let ReceiptEvent::Transfer(transfer) = event else {
            return None;
        };
        transfer.from.is_zero().then_some(Self {
            token: transfer.token,
            recipient: transfer.to,
            amount: transfer.amount,
        })
    }

    /// Return whether an event forwards this virtual recipient to its master.
    fn matches_forward(&self, event: &ReceiptEvent) -> bool {
        matches!(
            event,
            ReceiptEvent::Transfer(transfer)
                if transfer.token == self.token
                    && !transfer.from.is_zero()
                    && transfer.from == self.recipient
                    && !transfer.to.is_zero()
                    && transfer.to != self.recipient
                    && transfer.amount == self.amount
        )
    }

    /// Decode the Inbox outcome authenticating a mint.
    fn from_outcome(event: &ReceiptEvent) -> Option<Self> {
        match event {
            ReceiptEvent::Action(L2BridgeAction::Deposit {
                token,
                amount,
                result: DepositResult::Processed { recipient },
            })
            | ReceiptEvent::Action(L2BridgeAction::WithdrawalBounceBack {
                recipient,
                token,
                amount,
                status: WithdrawalBounceBackStatus::Processed,
            })
            | ReceiptEvent::Action(L2BridgeAction::RefundClaimed {
                recipient,
                token,
                amount,
            }) => Some(Self {
                token: *token,
                recipient: *recipient,
                amount: *amount,
            }),
            _ => None,
        }
    }
}

/// Reconcile every withdrawal in one receipt with distinct preceding debit-and-burn groups.
fn authenticate_receipt_withdrawals(
    transaction_hash: B256,
    receipt: &[ReceiptEvent],
) -> eyre::Result<()> {
    let burns = receipt
        .windows(3)
        .enumerate()
        .filter_map(|(start, events)| WithdrawalBurn::from_events(start, events))
        .collect::<Vec<_>>();
    let mut consumed = vec![false; burns.len()];

    for (request_index, event) in receipt.iter().enumerate() {
        let ReceiptEvent::Action(L2BridgeAction::WithdrawalRequested {
            origin: WithdrawalOrigin::User { sender, .. },
            token,
            principal,
            fee,
            ..
        }) = *event
        else {
            continue;
        };

        let total = principal + fee;
        if let Some(index) = matching_burn(&burns, &consumed, request_index, token, sender, total) {
            consumed[index] = true;
            continue;
        }

        let principal_burn =
            matching_burn(&burns, &consumed, request_index, token, sender, principal);
        let fee_burn = if fee.is_zero() {
            None
        } else {
            matching_fee_burn(&burns, &consumed, request_index, token, fee, principal_burn)
        };
        if let (Some(principal_burn), Some(fee_burn)) = (principal_burn, fee_burn) {
            consumed[principal_burn] = true;
            consumed[fee_burn] = true;
            continue;
        }

        eyre::bail!(
            "withdrawal in transaction {} has no matching debit and burn of {total} {token}",
            transaction_hash
        );
    }

    if burns.iter().enumerate().any(|(index, _)| !consumed[index]) {
        eyre::bail!(
            "transaction {} has an unexplained withdrawal debit and burn",
            transaction_hash
        );
    }

    // Outbox withdrawals are the only Sphere path that burns tokens.
    let in_withdrawal = |index: usize| {
        burns
            .iter()
            .any(|burn| (burn.start_index..burn.end_index).contains(&index))
    };
    if receipt
        .iter()
        .enumerate()
        .any(|(index, event)| event.reduces_supply() && !in_withdrawal(index))
    {
        eyre::bail!(
            "transaction {} has a token burn outside a withdrawal",
            transaction_hash
        );
    }
    Ok(())
}

/// Find one unconsumed debit-and-burn group preceding a withdrawal request.
fn matching_burn(
    burns: &[WithdrawalBurn],
    consumed: &[bool],
    request_index: usize,
    token: Address,
    owner: Address,
    amount: U256,
) -> Option<usize> {
    burns.iter().enumerate().find_map(|(index, observed)| {
        (!consumed[index]
            && observed.end_index <= request_index
            && observed.token == token
            && observed.owner == owner
            && observed.amount == amount)
            .then_some(index)
    })
}

/// Find an unconsumed sponsored-fee burn preceding a withdrawal request.
fn matching_fee_burn(
    burns: &[WithdrawalBurn],
    consumed: &[bool],
    request_index: usize,
    token: Address,
    amount: U256,
    excluded: Option<usize>,
) -> Option<usize> {
    burns.iter().enumerate().find_map(|(index, observed)| {
        (Some(index) != excluded
            && !consumed[index]
            && observed.end_index <= request_index
            && observed.token == token
            && observed.amount == amount
            && !observed.owner.is_zero())
        .then_some(index)
    })
}

/// One debit, transfer-to-zero, and burn sequence within a receipt.
struct WithdrawalBurn {
    start_index: usize,
    end_index: usize,
    token: Address,
    owner: Address,
    amount: U256,
}

impl WithdrawalBurn {
    /// Decode one adjacent debit and its two burn logs.
    fn from_events(start_index: usize, events: &[ReceiptEvent]) -> Option<Self> {
        let [debit, second, third] = events else {
            return None;
        };
        let ReceiptEvent::Transfer(debit) = *debit else {
            return None;
        };
        let (transfer, burn) = if debit.token == SPHERE_TOKEN_ADDRESS {
            (third, second)
        } else {
            (second, third)
        };
        let ReceiptEvent::Transfer(transfer) = *transfer else {
            return None;
        };
        let ReceiptEvent::TokenBurn {
            token: burn_token,
            from: burn_from,
            amount: burn_amount,
        } = *burn
        else {
            return None;
        };
        (debit.token == transfer.token
            && debit.token == burn_token
            && debit.to == SPHERE_OUTBOX_ADDRESS
            && transfer.from == SPHERE_OUTBOX_ADDRESS
            && transfer.to.is_zero()
            && burn_from == SPHERE_OUTBOX_ADDRESS
            && debit.amount == transfer.amount
            && debit.amount == burn_amount)
            .then_some(Self {
                start_index,
                end_index: start_index + events.len(),
                token: debit.token,
                owner: debit.from,
                amount: debit.amount,
            })
    }
}

/// Builds ordered event evidence while receipts are visited once.
#[derive(Default)]
pub(super) struct EventCollector {
    anchor: Option<L1Anchor>,
    transfers: Vec<TokenTransfer>,
    actions: Vec<L2BridgeAction>,
}

impl EventCollector {
    /// Decode recognized logs from one canonical receipt.
    pub(super) fn extract_receipt<T, R>(
        &mut self,
        transaction: &T,
        receipt: &R,
        block: u64,
        enabled_tokens: &mut BTreeSet<Address>,
    ) -> eyre::Result<()>
    where
        T: TxHashRef,
        R: TxReceipt<Log = Log>,
    {
        let successful = receipt.status();
        let transaction_hash = *transaction.tx_hash();
        let mut events = Vec::new();
        for log in receipt.logs() {
            let event = if successful {
                match log.address {
                    SPHERE_INBOX_ADDRESS => decode_inbox(log, block, enabled_tokens)?,
                    SPHERE_OUTBOX_ADDRESS => decode_outbox(log, block, transaction_hash)?,
                    _ => decode_token_event(log, block, enabled_tokens)?,
                }
            } else {
                decode_token_event(log, block, enabled_tokens)?
            };
            if let Some(event) = event {
                events.push(event);
            }
        }

        if !successful {
            eyre::ensure!(
                !events.iter().any(ReceiptEvent::reduces_supply),
                "failed transaction {} has a token burn",
                transaction_hash
            );
            self.transfers
                .extend(events.into_iter().filter_map(|event| {
                    let ReceiptEvent::Transfer(transfer) = event else {
                        return None;
                    };
                    Some(transfer)
                }));
            return Ok(());
        }

        authenticate_receipt_mints(transaction_hash, &events)?;
        authenticate_receipt_withdrawals(transaction_hash, &events)?;
        for event in events {
            match event {
                ReceiptEvent::Anchor(anchor) => {
                    eyre::ensure!(
                        self.anchor.is_none(),
                        "duplicate ArcAdvanced in block {block}"
                    );
                    self.anchor = Some(anchor);
                }
                ReceiptEvent::Action(action) => self.actions.push(action),
                ReceiptEvent::Transfer(transfer) => self.transfers.push(transfer),
                ReceiptEvent::TokenBurn { .. } => {}
            }
        }
        Ok(())
    }

    /// Require the L1 anchor and finish the ordered event bundle.
    pub(super) fn finish(self, block: u64) -> eyre::Result<super::L2BlockEvidence> {
        let anchor = self
            .anchor
            .ok_or_else(|| eyre::eyre!("block {block} is missing ArcAdvanced"))?;
        Ok(super::L2BlockEvidence {
            anchor: Some(anchor),
            transfers: self.transfers,
            actions: self.actions,
        })
    }
}

/// Decode one recognized Sphere Inbox log.
fn decode_inbox(
    log: &Log,
    block: u64,
    enabled_tokens: &mut BTreeSet<Address>,
) -> eyre::Result<Option<ReceiptEvent>> {
    let topic = log
        .topics()
        .first()
        .ok_or_else(|| eyre::eyre!("topicless SphereInbox log in block {block}"))?;
    Ok(Some(match *topic {
        ISphereInbox::ArcAdvanced_0::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::ArcAdvanced_0>(log, "ArcAdvanced_0", block)?;
            ReceiptEvent::Anchor(L1Anchor {
                arc_block_hash: event.arcBlockHash,
                arc_block_number: event.arcBlockNumber,
            })
        }
        ISphereInbox::ArcAdvanced_1::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::ArcAdvanced_1>(log, "ArcAdvanced_1", block)?;
            ReceiptEvent::Anchor(L1Anchor {
                arc_block_hash: event.arcBlockHash,
                arc_block_number: event.arcBlockNumber,
            })
        }
        ISphereInbox::DepositProcessed::SIGNATURE_HASH => {
            let event =
                decode_event::<ISphereInbox::DepositProcessed>(log, "DepositProcessed", block)?;
            ReceiptEvent::Action(L2BridgeAction::Deposit {
                token: event.token,
                amount: U256::from(event.amount),
                result: DepositResult::Processed {
                    recipient: event.to,
                },
            })
        }
        ISphereInbox::DepositFailed::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::DepositFailed>(log, "DepositFailed", block)?;
            ReceiptEvent::Action(L2BridgeAction::Deposit {
                token: event.token,
                amount: U256::from(event.amount),
                result: DepositResult::Failed,
            })
        }
        ISphereInbox::WithdrawalBounceBackProcessed::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::WithdrawalBounceBackProcessed>(
                log,
                "WithdrawalBounceBackProcessed",
                block,
            )?;
            ReceiptEvent::Action(L2BridgeAction::WithdrawalBounceBack {
                recipient: event.sphereFallbackRecipient,
                token: event.token,
                amount: U256::from(event.amount),
                status: WithdrawalBounceBackStatus::Processed,
            })
        }
        ISphereInbox::WithdrawalBounceBackPending::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::WithdrawalBounceBackPending>(
                log,
                "WithdrawalBounceBackPending",
                block,
            )?;
            ReceiptEvent::Action(L2BridgeAction::WithdrawalBounceBack {
                recipient: event.sphereFallbackRecipient,
                token: event.token,
                amount: U256::from(event.amount),
                status: WithdrawalBounceBackStatus::Pending,
            })
        }
        ISphereInbox::RefundClaimed::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::RefundClaimed>(log, "RefundClaimed", block)?;
            ReceiptEvent::Action(L2BridgeAction::RefundClaimed {
                recipient: event.recipient,
                token: event.token,
                amount: U256::from(event.amount),
            })
        }
        ISphereInbox::TokenEnabled::SIGNATURE_HASH => {
            let event = decode_event::<ISphereInbox::TokenEnabled>(log, "TokenEnabled", block)?;
            enabled_tokens.insert(event.token);
            return Ok(None);
        }
        ISphereInbox::DepositRejected::SIGNATURE_HASH => {
            eyre::bail!("unsupported DepositRejected in block {block}");
        }
        _ => {
            eyre::bail!("unsupported SphereInbox event {topic} in block {block}");
        }
    }))
}

/// Decode accounting evidence emitted by an enabled token.
fn decode_token_event(
    log: &Log,
    block: u64,
    enabled_tokens: &BTreeSet<Address>,
) -> eyre::Result<Option<ReceiptEvent>> {
    if !enabled_tokens.contains(&log.address) {
        return Ok(None);
    }
    match log.topics().first() {
        Some(topic) if *topic == NativeFiatTokenV2_2::Transfer::SIGNATURE_HASH => {
            let event = decode_event::<NativeFiatTokenV2_2::Transfer>(log, "Transfer", block)?;
            Ok(Some(ReceiptEvent::Transfer(TokenTransfer {
                token: log.address,
                from: event.from,
                to: event.to,
                amount: event.value,
            })))
        }
        Some(topic) if *topic == NativeFiatTokenV2_2::Burn::SIGNATURE_HASH => {
            let event = decode_event::<NativeFiatTokenV2_2::Burn>(log, "Burn", block)?;
            Ok(Some(ReceiptEvent::TokenBurn {
                token: log.address,
                from: event.burner,
                amount: event.amount,
            }))
        }
        _ => Ok(None),
    }
}

/// Decode one recognized Sphere Outbox log.
fn decode_outbox(
    log: &Log,
    block: u64,
    transaction_hash: B256,
) -> eyre::Result<Option<ReceiptEvent>> {
    let topic = log
        .topics()
        .first()
        .ok_or_else(|| eyre::eyre!("topicless SphereOutbox log in block {block}"))?;
    Ok(Some(match *topic {
        ISphereOutbox::WithdrawalRequested::SIGNATURE_HASH => {
            let event = decode_event::<ISphereOutbox::WithdrawalRequested>(
                log,
                "WithdrawalRequested",
                block,
            )?;
            let origin = match (event.sender.is_zero(), event.fallbackNonce == 0) {
                (true, true) => WithdrawalOrigin::DepositBounceBack,
                (false, false) => WithdrawalOrigin::User {
                    sender: event.sender,
                    sender_tag: SpherePortal::Withdrawal::sender_tag(
                        event.sender,
                        transaction_hash,
                        event.fallbackNonce,
                    ),
                },
                _ => {
                    eyre::bail!(
                        "invalid WithdrawalRequested origin in block {block}: sender {}, fallback nonce {}",
                        event.sender,
                        event.fallbackNonce,
                    );
                }
            };
            ReceiptEvent::Action(L2BridgeAction::WithdrawalRequested {
                withdrawal_index: event.withdrawalIndex,
                origin,
                token: event.token,
                principal: U256::from(event.amount),
                fee: U256::from(event.fee),
            })
        }
        ISphereOutbox::BatchFinalized::SIGNATURE_HASH => {
            decode_event::<ISphereOutbox::BatchFinalized>(log, "BatchFinalized", block)?;
            return Ok(None);
        }
        ISphereOutbox::ArcGasRateUpdated::SIGNATURE_HASH => {
            decode_event::<ISphereOutbox::ArcGasRateUpdated>(log, "ArcGasRateUpdated", block)?;
            return Ok(None);
        }
        ISphereOutbox::MaxWithdrawalsPerBlockUpdated::SIGNATURE_HASH => {
            decode_event::<ISphereOutbox::MaxWithdrawalsPerBlockUpdated>(
                log,
                "MaxWithdrawalsPerBlockUpdated",
                block,
            )?;
            return Ok(None);
        }
        _ => {
            eyre::bail!("unsupported SphereOutbox event {topic} in block {block}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction as _, TxLegacy, TxType};
    use alloy_eips::BlockNumHash;
    use alloy_primitives::{Bytes, LogData, Signature, TxKind, U256};
    use alloy_sol_types::{SolCall, SolEvent};
    use reth_ethereum_primitives::Receipt;
    use sphere_contracts::spheres::ARC_STATE_ADDRESS;
    use sphere_contracts::spheres::ArcState;
    use test_case::test_case;

    fn collect<T, R>(
        transactions: &[T],
        receipts: &[R],
        block: BlockNumHash,
    ) -> eyre::Result<super::super::L2BlockEvidence>
    where
        T: TxHashRef + alloy_consensus::Transaction,
        R: TxReceipt<Log = Log>,
    {
        crate::l2::collect_l2_block_evidence(transactions, receipts, block, [])
    }

    fn transaction() -> alloy_consensus::Signed<TxLegacy> {
        TxLegacy {
            to: TxKind::Call(SPHERE_INBOX_ADDRESS),
            ..Default::default()
        }
        .into_signed(Signature::test_signature())
    }

    fn anchor_log(number: u64) -> Log {
        Log {
            address: SPHERE_INBOX_ADDRESS,
            data: ISphereInbox::ArcAdvanced_1 {
                arcBlockHash: B256::repeat_byte(0xaa),
                arcBlockNumber: number,
                depositsProcessed: U256::from(2),
                newProcessedDepositQueueHash: B256::repeat_byte(0xbb),
                lastProcessedDepositNumber: 3,
                lastProcessedEnabledTokenCount: 4,
            }
            .encode_log_data(),
        }
    }

    fn receipt(logs: Vec<Log>) -> Receipt {
        Receipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 0,
            logs,
        }
    }

    fn event_log<E: SolEvent>(address: Address, event: E) -> Log {
        Log {
            address,
            data: event.encode_log_data(),
        }
    }

    fn withdrawal_request_log(sender: Address, fallback_nonce: u64) -> Log {
        event_log(
            SPHERE_OUTBOX_ADDRESS,
            ISphereOutbox::WithdrawalRequested {
                withdrawalIndex: 1,
                sender,
                token: SPHERE_TOKEN_ADDRESS,
                to: Address::ZERO,
                amount: 100,
                fee: 0,
                memo: B256::ZERO,
                gasLimit: 0,
                fallbackNonce: fallback_nonce,
                data: Default::default(),
                revealTo: Default::default(),
            },
        )
    }

    #[test]
    fn decodes_all_event_variants_in_canonical_order() {
        let token_a = SPHERE_TOKEN_ADDRESS;
        let token_b = Address::repeat_byte(0xb0);
        let recipient_a = Address::repeat_byte(0xaa);
        let recipient_b = Address::repeat_byte(0xbb);
        let logs = vec![
            anchor_log(100),
            event_log(
                token_b,
                NativeFiatTokenV2_2::Transfer {
                    from: Address::ZERO,
                    to: recipient_a,
                    value: U256::ONE,
                },
            ),
            event_log(
                token_a,
                NativeFiatTokenV2_2::Transfer {
                    from: Address::ZERO,
                    to: recipient_a,
                    value: U256::from(500),
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::DepositProcessed {
                    depositHash: B256::repeat_byte(0xd0),
                    sender: Address::ZERO,
                    to: recipient_a,
                    token: token_a,
                    amount: 500,
                    memo: B256::ZERO,
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::DepositFailed {
                    depositHash: B256::repeat_byte(0xd1),
                    sender: Address::ZERO,
                    token: token_b,
                    amount: 300,
                },
            ),
            event_log(
                token_a,
                NativeFiatTokenV2_2::Transfer {
                    from: Address::ZERO,
                    to: recipient_b,
                    value: U256::from(777),
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::WithdrawalBounceBackProcessed {
                    sphereFallbackRecipient: recipient_b,
                    token: token_a,
                    amount: 777,
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::WithdrawalBounceBackPending {
                    sphereFallbackRecipient: Address::ZERO,
                    token: token_b,
                    amount: 888,
                },
            ),
            event_log(
                token_a,
                NativeFiatTokenV2_2::Transfer {
                    from: Address::ZERO,
                    to: recipient_b,
                    value: U256::from(42),
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::RefundClaimed {
                    recipient: recipient_b,
                    token: token_a,
                    amount: 42,
                },
            ),
            event_log(
                SPHERE_INBOX_ADDRESS,
                ISphereInbox::TokenEnabled {
                    token: token_b,
                    name: "Token B".into(),
                    symbol: "TB".into(),
                    currency: "USD".into(),
                },
            ),
            event_log(
                SPHERE_OUTBOX_ADDRESS,
                ISphereOutbox::WithdrawalRequested {
                    withdrawalIndex: 3,
                    sender: Address::ZERO,
                    token: token_a,
                    to: Address::ZERO,
                    amount: 1000,
                    fee: 0,
                    memo: B256::ZERO,
                    gasLimit: 0,
                    fallbackNonce: 0,
                    data: Default::default(),
                    revealTo: Default::default(),
                },
            ),
            event_log(
                token_b,
                NativeFiatTokenV2_2::Transfer {
                    from: Address::repeat_byte(0x44),
                    to: SPHERE_OUTBOX_ADDRESS,
                    value: U256::from(2075),
                },
            ),
            event_log(
                token_b,
                NativeFiatTokenV2_2::Transfer {
                    from: SPHERE_OUTBOX_ADDRESS,
                    to: Address::ZERO,
                    value: U256::from(2075),
                },
            ),
            event_log(
                token_b,
                NativeFiatTokenV2_2::Burn {
                    burner: SPHERE_OUTBOX_ADDRESS,
                    amount: U256::from(2075),
                },
            ),
            event_log(
                SPHERE_OUTBOX_ADDRESS,
                ISphereOutbox::WithdrawalRequested {
                    withdrawalIndex: 4,
                    sender: Address::repeat_byte(0x44),
                    token: token_b,
                    to: Address::ZERO,
                    amount: 2000,
                    fee: 75,
                    memo: B256::ZERO,
                    gasLimit: 0,
                    fallbackNonce: 9,
                    data: Default::default(),
                    revealTo: Default::default(),
                },
            ),
            event_log(
                SPHERE_OUTBOX_ADDRESS,
                ISphereOutbox::BatchFinalized {
                    withdrawalQueueHash: B256::repeat_byte(0xcc),
                    withdrawalBatchIndex: 7,
                },
            ),
        ];
        let events = collect(
            &[transaction()],
            &[receipt(logs)],
            BlockNumHash::new(4, B256::repeat_byte(4)),
        )
        .unwrap();

        assert_eq!(events.l1_anchor().unwrap().arc_block_number, 100);
        assert_eq!(events.transfers.len(), 5);
        assert_eq!(events.actions.len(), 7);
        assert!(matches!(events.actions[0], L2BridgeAction::Deposit {
            token, amount, result: DepositResult::Processed { .. }
        } if token == token_a && amount == U256::from(500)));
        assert!(matches!(events.actions[1], L2BridgeAction::Deposit {
            token, amount, result: DepositResult::Failed
        } if token == token_b && amount == U256::from(300)));
        assert!(
            matches!(events.actions[2], L2BridgeAction::WithdrawalBounceBack {
            token, amount, status: WithdrawalBounceBackStatus::Processed, ..
        } if token == token_a && amount == U256::from(777))
        );
        assert!(
            matches!(events.actions[3], L2BridgeAction::WithdrawalBounceBack {
            token, amount, status: WithdrawalBounceBackStatus::Pending, ..
        } if token == token_b && amount == U256::from(888))
        );
        assert!(matches!(events.actions[4], L2BridgeAction::RefundClaimed {
            token, amount, ..
        } if token == token_a && amount == U256::from(42)));
        assert!(
            matches!(events.actions[5], L2BridgeAction::WithdrawalRequested {
            withdrawal_index: 3, origin: WithdrawalOrigin::DepositBounceBack, token, principal, fee,
        } if token == token_a && principal == U256::from(1000) && fee.is_zero())
        );
        assert!(
            matches!(events.actions[6], L2BridgeAction::WithdrawalRequested {
            withdrawal_index: 4, origin: WithdrawalOrigin::User { sender, sender_tag }, token, principal, fee,
        } if sender == Address::repeat_byte(0x44) && token == token_b
            && principal == U256::from(2000) && fee == U256::from(75)
            && sender_tag == SpherePortal::Withdrawal::sender_tag(sender, *transaction().tx_hash(), 9))
        );
    }

    #[test]
    fn checkpoint_only_blocks_require_the_exact_event_and_transaction_shape() {
        let header = alloy_consensus::Header {
            number: 109,
            ..Default::default()
        };
        let encoded = Bytes::from(alloy_rlp::encode(&header));
        let tx = TxLegacy {
            to: TxKind::Call(SPHERE_INBOX_ADDRESS),
            input: ISphereInbox::advanceArcHeadersCall {
                headers: vec![encoded.clone()],
            }
            .abi_encode()
            .into(),
            ..Default::default()
        }
        .into_signed(Signature::test_signature());
        let log = event_log(
            ARC_STATE_ADDRESS,
            ArcState::ArcBlockFinalized {
                blockHash: alloy_primitives::keccak256(&encoded),
                blockNumber: 109,
                stateRoot: header.state_root,
            },
        );
        let block = BlockNumHash::new(4, B256::ZERO);
        let events = collect(
            std::slice::from_ref(&tx),
            &[receipt(vec![log.clone()])],
            block,
        )
        .unwrap();
        assert!(events.l1_anchor().is_none());
        assert!(events.token_transfers().next().is_none());
        assert!(events.bridge_actions().next().is_none());

        // Missing anchors in ordinary blocks must still fail.
        assert!(collect(&[transaction()], &[receipt(vec![])], block).is_err());
        assert!(collect(std::slice::from_ref(&tx), &[receipt(vec![])], block).is_err());
        assert!(
            collect(
                std::slice::from_ref(&tx),
                &[receipt(vec![anchor_log(7)])],
                block
            )
            .is_err()
        );
        assert!(
            collect(
                std::slice::from_ref(&tx),
                &[receipt(vec![log.clone(), anchor_log(7)])],
                block
            )
            .is_err()
        );
        assert!(
            collect(
                &[tx.clone(), transaction()],
                &[receipt(vec![log.clone()]), receipt(vec![])],
                block,
            )
            .is_err()
        );
        let mut failed = receipt(vec![log.clone()]);
        failed.success = false;
        assert!(collect(std::slice::from_ref(&tx), &[failed], block).is_err());
        // A reverted user call later in a full block is not its opening system transaction.
        let mut reverted_user_call = receipt(vec![]);
        reverted_user_call.success = false;
        assert!(
            collect(
                &[transaction(), tx.clone()],
                &[receipt(vec![anchor_log(110)]), reverted_user_call],
                block,
            )
            .unwrap()
            .l1_anchor()
            .is_some()
        );
        let mut wrong_address = log;
        wrong_address.address = SPHERE_INBOX_ADDRESS;
        assert!(collect(&[tx], &[receipt(vec![wrong_address])], block).is_err());
    }

    #[test]
    fn rejects_missing_and_duplicate_anchor() {
        let block = BlockNumHash::new(4, B256::ZERO);
        let missing = collect(&[transaction()], &[receipt(vec![])], block).unwrap_err();
        assert!(missing.to_string().contains("missing ArcAdvanced"));

        let anchor = anchor_log(7);
        let duplicate = collect(
            &[transaction()],
            &[receipt(vec![anchor.clone(), anchor])],
            block,
        )
        .unwrap_err();
        assert!(duplicate.to_string().contains("duplicate ArcAdvanced"));
    }

    #[test_case(Address::ZERO, 1)]
    #[test_case(Address::repeat_byte(1), 0)]
    fn rejects_inconsistent_withdrawal_origins(sender: Address, fallback_nonce: u64) {
        let log = withdrawal_request_log(sender, fallback_nonce);
        let error = decode_outbox(&log, 4, B256::ZERO).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid WithdrawalRequested origin")
        );
    }

    #[test]
    fn decodes_and_ignores_batch_finalized() {
        let batch = event_log(
            SPHERE_OUTBOX_ADDRESS,
            ISphereOutbox::BatchFinalized {
                withdrawalQueueHash: B256::ZERO,
                withdrawalBatchIndex: 0,
            },
        );
        let events = collect(
            &[transaction()],
            &[receipt(vec![anchor_log(7), batch])],
            BlockNumHash::new(4, B256::ZERO),
        )
        .unwrap();
        assert!(events.actions.is_empty());
        assert!(events.transfers.is_empty());
    }

    #[test]
    fn rejects_malformed_known_event() {
        let malformed = Log {
            address: SPHERE_INBOX_ADDRESS,
            data: LogData::new_unchecked(
                vec![ISphereInbox::ArcAdvanced_1::SIGNATURE_HASH],
                Bytes::from(vec![0xde, 0xad]),
            ),
        };
        let error = collect(
            &[transaction()],
            &[receipt(vec![malformed])],
            BlockNumHash::new(4, B256::ZERO),
        )
        .unwrap_err();
        assert!(error.to_string().contains("malformed ArcAdvanced"));
    }

    #[test]
    fn rejects_non_canonical_trailing_event_data() {
        let anchor = anchor_log(7);
        let mut data = anchor.data.data.to_vec();
        data.extend([0; 32]);
        let trailing = Log {
            address: anchor.address,
            data: LogData::new_unchecked(anchor.topics().to_vec(), Bytes::from(data)),
        };
        let error = collect(
            &[transaction()],
            &[receipt(vec![trailing])],
            BlockNumHash::new(4, B256::ZERO),
        )
        .unwrap_err();
        assert!(error.to_string().contains("non-canonical ArcAdvanced"));
    }

    #[test]
    fn rejects_unknown_protocol_logs_and_ignores_other_emitters() {
        let anchor = anchor_log(7);
        for unsupported in [
            Log {
                address: SPHERE_INBOX_ADDRESS,
                data: LogData::new_unchecked(vec![B256::repeat_byte(0x99)], Bytes::new()),
            },
            Log {
                address: SPHERE_OUTBOX_ADDRESS,
                data: LogData::new_unchecked(vec![], Bytes::new()),
            },
        ] {
            assert!(
                collect(
                    &[transaction()],
                    &[receipt(vec![unsupported])],
                    BlockNumHash::new(4, B256::ZERO),
                )
                .is_err()
            );
        }
        let logs = vec![
            Log {
                address: Address::repeat_byte(0x88),
                data: anchor.data.clone(),
            },
            anchor,
        ];
        let events = collect(
            &[transaction()],
            &[receipt(logs)],
            BlockNumHash::new(4, B256::ZERO),
        )
        .unwrap();
        assert!(events.actions.is_empty());
        assert!(events.transfers.is_empty());
    }

    #[test]
    fn rejects_transaction_receipt_count_mismatch() {
        let error = collect::<_, Receipt>(&[transaction()], &[], BlockNumHash::new(4, B256::ZERO))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("has 1 transactions but 0 receipts")
        );
    }

    #[test]
    fn retains_recognized_events_across_ignored_logs() {
        let anchor = anchor_log(7);
        let noise = Log {
            address: Address::repeat_byte(9),
            data: anchor.data.clone(),
        };
        let receipt = Receipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![noise, anchor],
        };
        let tx = transaction();
        let events = collect(
            std::slice::from_ref(&tx),
            &[receipt],
            BlockNumHash::new(4, B256::repeat_byte(4)),
        )
        .unwrap();
        assert!(events.actions.is_empty());
        assert!(events.transfers.is_empty());
        assert_eq!(events.l1_anchor().unwrap().block_number(), 7);
    }

    #[test]
    fn failed_receipt_retains_fee_transfer_without_protocol_evidence() {
        let token = SPHERE_TOKEN_ADDRESS;
        let fee_payer = Address::repeat_byte(1);
        let beneficiary = Address::repeat_byte(2);
        let failed_fee = TokenTransfer {
            token,
            from: fee_payer,
            to: beneficiary,
            amount: U256::from(3),
        };
        let successful_fee = TokenTransfer {
            token,
            from: fee_payer,
            to: beneficiary,
            amount: U256::from(2),
        };
        let failed = Receipt {
            tx_type: TxType::Legacy,
            success: false,
            cumulative_gas_used: 0,
            logs: vec![
                anchor_log(6),
                event_log(
                    token,
                    NativeFiatTokenV2_2::Transfer {
                        from: failed_fee.from,
                        to: failed_fee.to,
                        value: failed_fee.amount,
                    },
                ),
            ],
        };
        let successful = Receipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![
                anchor_log(7),
                event_log(
                    token,
                    NativeFiatTokenV2_2::Transfer {
                        from: successful_fee.from,
                        to: successful_fee.to,
                        value: successful_fee.amount,
                    },
                ),
            ],
        };
        let events = collect(
            &[transaction(), transaction()],
            &[failed, successful],
            BlockNumHash::new(4, B256::repeat_byte(4)),
        )
        .unwrap();

        assert_eq!(events.l1_anchor().unwrap().block_number(), 7);
        assert!(events.actions.is_empty());
        assert_eq!(events.transfers, vec![failed_fee, successful_fee]);
    }

    fn transfer(token: Address, from: Address, to: Address, amount: U256) -> ReceiptEvent {
        ReceiptEvent::Transfer(TokenTransfer {
            token,
            from,
            to,
            amount,
        })
    }

    fn burn(token: Address, owner: Address, amount: u64) -> Vec<ReceiptEvent> {
        let amount = U256::from(amount);
        vec![
            transfer(token, owner, SPHERE_OUTBOX_ADDRESS, amount),
            transfer(token, SPHERE_OUTBOX_ADDRESS, Address::ZERO, amount),
            ReceiptEvent::TokenBurn {
                token,
                from: SPHERE_OUTBOX_ADDRESS,
                amount,
            },
        ]
    }

    fn withdrawal(token: Address, sender: Address, principal: u128, fee: u128) -> ReceiptEvent {
        let origin = if sender.is_zero() {
            WithdrawalOrigin::DepositBounceBack
        } else {
            WithdrawalOrigin::User {
                sender,
                sender_tag: B256::ZERO,
            }
        };
        ReceiptEvent::Action(L2BridgeAction::WithdrawalRequested {
            withdrawal_index: 0,
            origin,
            token,
            principal: U256::from(principal),
            fee: U256::from(fee),
        })
    }

    fn authenticate_withdrawals(events: Vec<ReceiptEvent>) -> eyre::Result<()> {
        authenticate_receipt_withdrawals(B256::repeat_byte(1), &events)
    }

    fn authenticate_mints(events: Vec<ReceiptEvent>) -> eyre::Result<()> {
        authenticate_receipt_mints(B256::repeat_byte(1), &events)
    }

    #[test]
    fn authenticates_inbox_mints() {
        let token = Address::repeat_byte(1);
        let recipient = Address::repeat_byte(2);
        let outcome = ReceiptEvent::Action(L2BridgeAction::Deposit {
            token,
            amount: U256::from(10),
            result: DepositResult::Processed { recipient },
        });
        let mint = transfer(token, Address::ZERO, recipient, U256::from(10));

        authenticate_mints(vec![mint, outcome]).unwrap();
    }

    #[test]
    fn rejects_unmatched_inbox_mints() {
        let token = Address::repeat_byte(1);
        let outcome = ReceiptEvent::Action(L2BridgeAction::Deposit {
            token,
            amount: U256::from(10),
            result: DepositResult::Processed {
                recipient: Address::repeat_byte(2),
            },
        });
        let wrong_mint = transfer(
            token,
            Address::ZERO,
            Address::repeat_byte(3),
            U256::from(10),
        );
        let unexpected_mint = transfer(
            token,
            Address::ZERO,
            Address::repeat_byte(4),
            U256::from(10),
        );

        assert!(authenticate_mints(vec![wrong_mint, outcome]).is_err());
        assert!(authenticate_mints(vec![unexpected_mint]).is_err());
    }

    #[test]
    fn authenticates_mints_to_virtual_recipients() {
        let token = Address::repeat_byte(1);
        let recipient = Address::repeat_byte(2);
        let master = Address::repeat_byte(3);
        let amount = U256::from(10);
        let mint = transfer(token, Address::ZERO, recipient, amount);
        let forward = transfer(token, recipient, master, amount);
        let outcome = ReceiptEvent::Action(L2BridgeAction::Deposit {
            token,
            amount,
            result: DepositResult::Processed { recipient },
        });

        authenticate_mints(vec![mint, forward, outcome]).unwrap();
    }

    #[test]
    fn rejects_inbox_mints_paired_across_receipts() {
        let token = SPHERE_TOKEN_ADDRESS;
        let recipient = Address::repeat_byte(2);
        let mint = event_log(
            token,
            NativeFiatTokenV2_2::Transfer {
                from: Address::ZERO,
                to: recipient,
                value: U256::from(10),
            },
        );
        let outcome = event_log(
            SPHERE_INBOX_ADDRESS,
            ISphereInbox::DepositProcessed {
                depositHash: B256::ZERO,
                sender: Address::ZERO,
                to: recipient,
                token,
                amount: 10,
                memo: B256::ZERO,
            },
        );

        assert!(
            collect(
                &[transaction(), transaction()],
                &[receipt(vec![anchor_log(7), mint]), receipt(vec![outcome])],
                BlockNumHash::new(4, B256::ZERO),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_inbox_mints_with_an_intervening_recognized_event() {
        let token = Address::repeat_byte(1);
        let recipient = Address::repeat_byte(2);
        let mint = transfer(token, Address::ZERO, recipient, U256::from(10));
        let unrelated = transfer(token, recipient, Address::repeat_byte(3), U256::ONE);
        let outcome = ReceiptEvent::Action(L2BridgeAction::Deposit {
            token,
            amount: U256::from(10),
            result: DepositResult::Processed { recipient },
        });

        assert!(authenticate_mints(vec![mint, unrelated, outcome]).is_err());
    }

    #[test]
    fn rejects_zero_recipient_mint_hiding_another_mint() {
        let token = Address::repeat_byte(1);
        let amount = U256::from(10);
        let zero_mint = transfer(token, Address::ZERO, Address::ZERO, amount);
        let hidden_mint = transfer(token, Address::ZERO, Address::repeat_byte(2), amount);
        let outcome = ReceiptEvent::Action(L2BridgeAction::Deposit {
            token,
            amount,
            result: DepositResult::Processed {
                recipient: Address::ZERO,
            },
        });

        let error = authenticate_mints(vec![zero_mint, hidden_mint, outcome]).unwrap_err();
        assert!(error.to_string().contains("unexplained mint"), "{error}");
    }

    #[test]
    fn rejects_token_burn_outside_withdrawal() {
        let token = Address::repeat_byte(1);
        let owner = Address::repeat_byte(2);
        let amount = U256::from(10);
        let token_burn = ReceiptEvent::TokenBurn {
            token,
            from: owner,
            amount,
        };
        let burn_transfer = transfer(token, owner, Address::ZERO, amount);

        for events in [
            vec![burn_transfer, token_burn],
            vec![token_burn],
            vec![burn_transfer],
        ] {
            let error = authenticate_withdrawals(events).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("token burn outside a withdrawal"),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_token_burn_beside_authenticated_withdrawal() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 100);
        events.push(withdrawal(token, sender, 100, 0));
        events.push(ReceiptEvent::TokenBurn {
            token,
            from: sender,
            amount: U256::ONE,
        });

        let error = authenticate_withdrawals(events).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("token burn outside a withdrawal"),
            "{error}"
        );
    }

    #[test]
    fn rejects_token_burn_in_failed_receipt() {
        let token = SPHERE_TOKEN_ADDRESS;
        let owner = Address::repeat_byte(1);
        let failed = Receipt {
            tx_type: TxType::Legacy,
            success: false,
            cumulative_gas_used: 0,
            logs: vec![
                event_log(
                    token,
                    NativeFiatTokenV2_2::Transfer {
                        from: owner,
                        to: Address::ZERO,
                        value: U256::ONE,
                    },
                ),
                event_log(
                    token,
                    NativeFiatTokenV2_2::Burn {
                        burner: owner,
                        amount: U256::ONE,
                    },
                ),
            ],
        };

        let error = collect(
            &[transaction(), transaction()],
            &[failed, receipt(vec![anchor_log(7)])],
            BlockNumHash::new(4, B256::repeat_byte(4)),
        )
        .unwrap_err();
        assert!(error.to_string().contains("token burn"), "{error:#}");
    }

    #[test]
    fn authenticates_sender_paid_withdrawal() {
        let token = SPHERE_TOKEN_ADDRESS;
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 105);
        assert!(WithdrawalBurn::from_events(0, &events).is_none());
        events.swap(1, 2);
        events.push(withdrawal(token, sender, 100, 5));
        authenticate_withdrawals(events).unwrap();
    }

    #[test]
    fn authenticates_sponsored_withdrawal() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let fee_payer = Address::repeat_byte(3);
        let mut events = burn(token, sender, 100);
        events.extend(burn(token, fee_payer, 5));
        events.push(withdrawal(token, sender, 100, 5));
        authenticate_withdrawals(events).unwrap();
    }

    #[test]
    fn rejects_wrong_withdrawal_burn_amount() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 101);
        events.push(withdrawal(token, sender, 100, 0));
        assert!(authenticate_withdrawals(events).is_err());
    }

    #[test]
    fn authenticates_multiple_withdrawals_in_one_transaction() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 100);
        events.push(withdrawal(token, sender, 100, 0));
        events.extend(burn(token, sender, 205));
        events.push(withdrawal(token, sender, 200, 5));
        authenticate_withdrawals(events).unwrap();
    }

    #[test]
    fn authenticates_withdrawal_after_unrelated_receipt_events() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 100);
        events.push(ReceiptEvent::Action(L2BridgeAction::RefundClaimed {
            recipient: sender,
            token,
            amount: U256::ONE,
        }));
        events.push(withdrawal(token, sender, 100, 0));

        authenticate_withdrawals(events).unwrap();
    }

    #[test]
    fn rejects_reusing_one_burn_for_multiple_withdrawals() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 100);
        events.push(withdrawal(token, sender, 100, 0));
        events.push(withdrawal(token, sender, 100, 0));

        assert!(authenticate_withdrawals(events).is_err());
    }

    #[test]
    fn rejects_unexplained_withdrawal_burn() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);

        assert!(authenticate_withdrawals(burn(token, sender, 100)).is_err());
    }

    #[test]
    fn rejects_missing_withdrawal_burn_event() {
        let token = Address::repeat_byte(1);
        let sender = Address::repeat_byte(2);
        let mut events = burn(token, sender, 100);
        events.remove(2);
        events.push(withdrawal(token, sender, 100, 0));
        assert!(authenticate_withdrawals(events).is_err());
    }

    #[test]
    fn deposit_bounce_back_does_not_require_a_burn() {
        let event = withdrawal(Address::repeat_byte(1), Address::ZERO, 100, 0);
        authenticate_withdrawals(vec![event]).unwrap();
    }
}
