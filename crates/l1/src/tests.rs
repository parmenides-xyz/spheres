use alloy_consensus::Sealable as _;
use alloy_transport::mock::Asserter;
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use std::time::Duration;
use super::*;
use crate::abi::DepositType;
use alloy_consensus::{Header, Receipt, ReceiptEnvelope, ReceiptWithBloom};
use alloy_eips::NumHash;
use alloy_primitives::address;
use alloy_primitives::{Address, B256, Bloom, Bytes};
use alloy_rpc_types_eth::TransactionReceipt;
use serde::Deserialize;

fn make_test_header(number: u64) -> Header {
    Header {
        number,
        ..Default::default()
    }
}

fn make_test_receipt(
    block_number: u64,
    block_hash: B256,
    tx_hash: B256,
    tx_index: u64,
    cumulative_gas_used: u64,
    logs_bloom: Bloom,
) -> TransactionReceipt {
    TransactionReceipt {
        inner: ReceiptEnvelope::Legacy(ReceiptWithBloom::new(
            Receipt {
                status: true.into(),
                cumulative_gas_used,
                logs: vec![],
            },
            logs_bloom,
        )),
        transaction_hash: tx_hash,
        transaction_index: Some(tx_index),
        block_hash: Some(block_hash),
        block_number: Some(block_number),
        gas_used: cumulative_gas_used,
        effective_gas_price: 0,
        blob_gas_used: None,
        blob_gas_price: None,
        from: Address::ZERO,
        to: Some(Address::ZERO),
        contract_address: None,
    }
}

fn calculate_test_receipts_root(receipts: &[TransactionReceipt]) -> B256 {
    let receipts = receipts
        .iter()
        .map(|receipt| receipt.inner.clone().into_primitives_receipt())
        .collect::<Vec<_>>();
    alloy_consensus::proofs::calculate_receipt_root(&receipts)
}

#[test]
fn verify_receipts_accepts_matching_root_and_logs_bloom() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![
        make_test_receipt(
            block_number,
            block_hash,
            B256::with_last_byte(0x01),
            0,
            21_000,
            Bloom::ZERO,
        ),
        make_test_receipt(
            block_number,
            block_hash,
            B256::with_last_byte(0x02),
            1,
            42_000,
            Bloom::ZERO,
        ),
    ];
    let receipts_root = calculate_test_receipts_root(&receipts);

    verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &receipts)
        .expect("matching receipts root should validate");
}

#[test]
fn verify_receipts_rejects_receipts_root_mismatch() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::ZERO,
    )];

    let err =
        verify_receipts_against_header(block, B256::with_last_byte(0xff), Bloom::ZERO, &receipts)
            .expect_err("mismatched receipts root should fail");

    assert!(
        err.to_string().contains("receipt root mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_receipts_rejects_changed_receipt_bloom() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::ZERO,
    )];
    let receipts_root = calculate_test_receipts_root(&receipts);
    let mut tampered_receipts = receipts;
    tampered_receipts[0]
        .inner
        .as_receipt_with_bloom_mut()
        .unwrap()
        .logs_bloom = Bloom::repeat_byte(0x01);

    let err = verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &tampered_receipts)
        .expect_err("tampered receipt bloom should fail");

    assert!(
        err.to_string().contains("receipt root mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_receipts_rejects_logs_bloom_mismatch() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::repeat_byte(0x01),
    )];
    let receipts_root = calculate_test_receipts_root(&receipts);

    let err = verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &receipts)
        .expect_err("mismatched header logs bloom should fail");

    assert!(
        err.to_string().contains("logs bloom mismatch"),
        "unexpected error: {err}"
    );
}

fn make_withdrawal_bounce_back(amount: u128) -> L1Deposit {
    L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount,
        fee: 0,
    })
}

#[tokio::test]
async fn l1_block_tracker_waits_for_exact_observation() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let waiting = tracker.clone();
    let waiter = tokio::spawn(async move { waiting.wait_for(anchor).await });

    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    tracker.record(anchor).unwrap();
    waiter.await.unwrap().unwrap();
}

#[tokio::test]
async fn l1_block_tracker_returns_receipt_authenticated_portal_events() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let events = L1PortalEvents::from_deposits(vec![make_withdrawal_bounce_back(100)]);
    tracker
        .record_with_portal_events(anchor, events.clone())
        .unwrap();

    let observed = tracker.wait_for_portal_events(anchor).await.unwrap();
    assert_eq!(observed.deposits.len(), 1);
    assert_eq!(
        observed.deposits[0].to_abi_queued_deposit(),
        events.deposits[0].to_abi_queued_deposit()
    );
}

#[test]
fn l1_block_tracker_retains_authenticated_portal_logs_after_consumption() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let parent_hash = B256::with_last_byte(0x09);
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let log = alloy_primitives::Log::new_unchecked(
        portal,
        vec![B256::with_last_byte(1)],
        Default::default(),
    );
    tracker
        .record_with_portal_evidence(
            anchor,
            parent_hash,
            0,
            L1PortalEvents::default(),
            vec![log.clone()],
        )
        .unwrap();

    let observed = tracker.authenticated_portal_logs(anchor).unwrap().unwrap();
    assert_eq!(observed.parent_hash, parent_hash);
    assert_eq!(observed.logs, vec![log.clone()]);

    tracker.prune_through(anchor.number);
    assert_eq!(tracker.observed_hash(anchor.number), None);
    assert_eq!(
        tracker
            .authenticated_portal_logs(anchor)
            .unwrap()
            .unwrap()
            .logs,
        vec![log]
    );
}

#[tokio::test]
async fn l1_block_tracker_rejects_conflicts_and_missing_heights() {
    let tracker = L1BlockTracker::default();
    let block_10 = NumHash::new(10, B256::with_last_byte(0x10));
    let block_11 = NumHash::new(11, B256::with_last_byte(0x11));
    tracker.record(block_10).unwrap();
    tracker.record(block_11).unwrap();
    tracker.record(block_11).unwrap();

    let conflict = NumHash::new(11, B256::with_last_byte(0xff));
    assert!(tracker.wait_for(conflict).await.is_err());
    assert!(
        tracker
            .record(NumHash::new(13, B256::with_last_byte(0x13)))
            .is_err()
    );
}

#[tokio::test]
async fn l1_block_tracker_prunes_only_consumed_observations() {
    let tracker = L1BlockTracker::default();
    for number in 10..=12 {
        tracker
            .record(NumHash::new(number, B256::with_last_byte(number as u8)))
            .unwrap();
    }

    tracker.prune_through(10);
    assert_eq!(tracker.observed_hash(10), None);
    assert_eq!(tracker.observed_hash(11), Some(B256::with_last_byte(11)));
    assert_eq!(tracker.latest().unwrap().number, 12);
    assert!(
        tracker
            .wait_for(NumHash::new(10, B256::with_last_byte(10)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn l1_block_tracker_backpressures_at_one_hour_lookahead() {
    let tracker = L1BlockTracker::default();
    let consumed = 100;
    tracker.initialize_consumed_through(consumed);

    for number in consumed + 1..=consumed + MAX_L1_LOOKAHEAD_BLOCKS {
        tracker
            .record(NumHash::new(number, B256::with_last_byte(number as u8)))
            .unwrap();
    }

    let blocked_number = consumed + MAX_L1_LOOKAHEAD_BLOCKS + 1;
    assert!(!tracker.has_capacity_for(blocked_number));
    assert_eq!(tracker.next_observation_number(), Some(blocked_number));
    assert!(
        tracker
            .record(NumHash::new(
                blocked_number,
                B256::with_last_byte(blocked_number as u8),
            ))
            .is_err()
    );

    let waiting = tracker.clone();
    let waiter = tokio::spawn(async move { waiting.wait_for_capacity(blocked_number).await });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    tracker.prune_through(consumed + 1);
    waiter.await.unwrap().unwrap();
    assert!(tracker.has_capacity_for(blocked_number));
}

#[test]
fn l1_block_tracker_finalized_target_is_monotonic() {
    let tracker = L1BlockTracker::default();
    assert_eq!(tracker.finalized_target(), None);

    tracker.record_finalized_target(200);
    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 200,
            ready: false,
        })
    );
    tracker.mark_finalized_target_ready(200).unwrap();
    tracker.record_finalized_target(199);
    tracker.record_finalized_target(200);

    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 200,
            ready: true,
        })
    );

    tracker.record_finalized_target(201);
    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 201,
            ready: false,
        })
    );
}

#[test]
fn l1_block_tracker_rejects_first_observation_above_persisted_successor() {
    let tracker = L1BlockTracker::default();
    tracker.initialize_consumed_through(10);

    let skipped = tracker
        .record(NumHash::new(12, B256::with_last_byte(12)))
        .unwrap_err();
    assert!(
        skipped
            .to_string()
            .contains("non-contiguous first L1 observation")
    );
    assert_eq!(tracker.latest(), None);
    assert_eq!(tracker.next_observation_number(), Some(11));

    tracker
        .record(NumHash::new(11, B256::with_last_byte(11)))
        .unwrap();
    assert_eq!(tracker.latest().unwrap().number, 11);
}

#[test]
fn l1_block_tracker_applies_only_newer_portal_pause_observations() {
    let tracker = L1BlockTracker::default();
    let block = |number: u64| NumHash::new(number, B256::with_last_byte(number as u8));
    assert!(!tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), None);

    assert!(tracker.observe_portal_pause(block(11), true).unwrap());
    assert!(tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), Some(block(11)));

    // Replayed older events cannot regress the finalized state.
    assert!(!tracker.observe_portal_pause(block(10), false).unwrap());
    assert!(tracker.portal_paused());
    // A repeated observation is idempotent and reports no change.
    assert!(!tracker.observe_portal_pause(block(11), true).unwrap());
    assert!(!tracker.observe_portal_pause(block(12), true).unwrap());
    assert_eq!(tracker.portal_pause_block(), Some(block(12)));

    assert!(tracker.observe_portal_pause(block(13), false).unwrap());
    assert!(!tracker.portal_paused());
}

#[test]
fn l1_block_tracker_rejects_conflicting_portal_pause_observations() {
    let tracker = L1BlockTracker::default();
    let block = NumHash::new(11, B256::repeat_byte(1));
    tracker.observe_portal_pause(block, true).unwrap();

    assert!(tracker.observe_portal_pause(block, false).is_err());
    assert!(
        tracker
            .observe_portal_pause(NumHash::new(11, B256::repeat_byte(2)), true)
            .is_err()
    );
    assert!(tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), Some(block));
}

fn make_chained_header(number: u64, parent_hash: B256) -> Header {
    Header {
        number,
        parent_hash,
        ..Default::default()
    }
}

fn seal(header: Header) -> SealedHeader<Header> {
    SealedHeader::seal_slow(header)
}

#[test]
fn finalized_queue_tracks_tip_after_consumption() {
    let queue = DepositQueue::new();
    assert!(queue.last_enqueued().is_none());

    let h100 = make_test_header(100);
    let h100_hash = h100.hash_slow();
    queue.enqueue(h100, L1PortalEvents::default());

    let h101 = make_chained_header(101, h100_hash);
    let h101_hash = h101.hash_slow();
    queue.enqueue(h101, L1PortalEvents::default());

    confirm_shared(&queue);
    confirm_shared(&queue);
    assert!(queue.peek().is_none());
    assert_eq!(
        queue.last_enqueued(),
        Some(NumHash::new(101, h101_hash)),
        "the subscriber high-water mark must survive consumption"
    );

    queue.enqueue(
        make_chained_header(102, h101_hash),
        L1PortalEvents::default(),
    );
}

#[test]
fn external_enqueue_reports_discontinuity_without_panicking() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    assert!(
        queue
            .try_enqueue_sealed(seal(h10), L1PortalEvents::default())
            .unwrap()
    );

    let err = queue
        .try_enqueue_sealed(
            seal(make_chained_header(12, h10_hash)),
            L1PortalEvents::default(),
        )
        .expect_err("external input must report a gap");
    assert!(
        err.to_string()
            .contains("non-contiguous finalized L1 block")
    );
}

#[test]
fn external_enqueue_accepts_duplicate_producers() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    let duplicate = seal(h10);
    assert!(
        queue
            .try_enqueue_sealed(duplicate.clone(), L1PortalEvents::default())
            .unwrap()
    );
    for header in [h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }
    assert!(
        !queue
            .try_enqueue_sealed(duplicate, L1PortalEvents::default())
            .unwrap()
    );
    assert_eq!(queue.peek().unwrap().header.number(), 10);
}

#[test]
fn confirm_operational_through_is_idempotent_and_drains_stale_entries() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    let anchor = seal(h12.clone()).num_hash();
    for header in [h10, h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }

    queue.confirm_operational_through(anchor).unwrap();
    assert!(queue.peek().is_none());
    queue.confirm_operational_through(anchor).unwrap();
}

#[test]
fn canonical_import_reconciliation_is_idempotent_across_checkpoint_and_full_blocks() {
    let queue = DepositQueue::new();
    let first = SealedHeader::seal_slow(make_test_header(1));
    let second = SealedHeader::seal_slow(make_chained_header(2, first.hash()));
    let third = SealedHeader::seal_slow(make_chained_header(3, second.hash()));
    for header in [&first, &second, &third] {
        queue
            .try_enqueue_sealed(header.clone(), L1PortalEvents::default())
            .unwrap();
    }

    queue.defer_through(second.num_hash()).unwrap();
    queue.defer_through(second.num_hash()).unwrap();
    assert_eq!(queue.peek().unwrap().header.num_hash(), third.num_hash());
    assert_eq!(queue.operational_work(third.num_hash()).unwrap().len(), 2);

    queue.confirm_operational_through(third.num_hash()).unwrap();
    queue.confirm_operational_through(third.num_hash()).unwrap();
    assert!(queue.peek().is_none());

    let fourth = SealedHeader::seal_slow(make_chained_header(4, third.hash()));
    let fifth = SealedHeader::seal_slow(make_chained_header(5, fourth.hash()));
    queue
        .try_enqueue_sealed(fourth.clone(), L1PortalEvents::default())
        .unwrap();
    queue.defer_through(fourth.num_hash()).unwrap();
    queue
        .try_enqueue_sealed(fifth, L1PortalEvents::default())
        .unwrap();

    // A late replay of block 3 must preserve block 4's newer deferred work.
    queue.confirm_operational_through(third.num_hash()).unwrap();
    let fifth = queue.peek().unwrap().header.num_hash();
    assert_eq!(queue.operational_work(fifth).unwrap().len(), 2);
}

#[test]
fn deferred_checkpoint_work_survives_until_operational_confirmation() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    for header in [h10, h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }

    let first = queue.peek().unwrap();
    queue.defer_through(first.header.num_hash()).unwrap();
    let second = queue.peek().unwrap();
    queue.defer_through(second.header.num_hash()).unwrap();
    let current = queue.peek().unwrap();
    let work = queue.operational_work(current.header.num_hash()).unwrap();
    assert_eq!(
        work.iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![11, 12]
    );

    queue
        .confirm_operational(current.header.num_hash())
        .unwrap();
    assert!(queue.peek().is_none());
}

#[test]
fn restart_can_seed_deferred_checkpoint_work() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let mut deferred = crate::queue::DeferredPortalWork::new(L1BlockDeposits {
        header: seal(h10),
        events: L1PortalEvents::default(),
    });
    deferred.push(L1BlockDeposits {
        header: seal(h11),
        events: L1PortalEvents::default(),
    });
    queue.restore_deferred(deferred).unwrap();

    let h12 = make_chained_header(12, queue.last_enqueued().unwrap().hash);
    queue
        .try_enqueue_sealed(seal(h12), L1PortalEvents::default())
        .unwrap();
    let current = queue.peek().unwrap();
    assert_eq!(
        queue
            .operational_work(current.header.num_hash())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn deferred_empty_blocks_use_constant_space() {
    let mut queue = PendingDeposits::default();
    let mut parent_hash = B256::ZERO;
    for number in 1..=10_000 {
        let header = if number == 1 {
            make_test_header(number)
        } else {
            make_chained_header(number, parent_hash)
        };
        let header = seal(header);
        let anchor = header.num_hash();
        parent_hash = anchor.hash;
        queue
            .try_enqueue(header, L1PortalEvents::default())
            .unwrap();
        queue.defer_through(anchor).unwrap();
    }

    assert_eq!(queue.deferred_event_block_len(), 0);
}

#[test]
fn confirm_operational_through_rejects_a_conflicting_anchor() {
    let queue = DepositQueue::new();
    queue
        .try_enqueue_sealed(seal(make_test_header(10)), L1PortalEvents::default())
        .unwrap();

    let err = queue
        .confirm_operational_through(NumHash::new(10, B256::repeat_byte(0xab)))
        .expect_err("a different hash at the same height must fail");
    assert!(err.to_string().contains("deposit queue holds L1 block 10"));
    assert_eq!(queue.peek().unwrap().header.number(), 10);
}

#[test]
#[should_panic(expected = "finalized L1 queue invariant violated")]
fn finalized_deposit_queue_panics_on_discontinuity() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());
    queue.enqueue(make_chained_header(12, h10_hash), L1PortalEvents::default());
}

#[test]
fn finalized_queue_accepts_only_contiguous_blocks() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();

    assert!(
        queue
            .try_enqueue(seal(h10), L1PortalEvents::default())
            .expect("first finalized block should enqueue")
    );
    assert!(
        queue
            .try_enqueue(
                seal(make_chained_header(11, h10_hash)),
                L1PortalEvents::default(),
            )
            .expect("child finalized block should enqueue")
    );
    assert_eq!(queue.pending_len(), 2);
}

#[test]
fn finalized_queue_tip_redelivery_is_idempotent() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);

    assert!(
        queue
            .try_enqueue(seal(h10.clone()), L1PortalEvents::default())
            .expect("first finalized block should enqueue")
    );
    assert!(
        !queue
            .try_enqueue(seal(h10), L1PortalEvents::default())
            .expect("exact tip redelivery should be accepted")
    );
    assert_eq!(queue.pending_len(), 1);
}

#[test]
fn finalized_queue_rejects_gap_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .try_enqueue(
            seal(make_chained_header(12, h10_hash)),
            L1PortalEvents::default(),
        )
        .expect_err("a finalized height gap must be fatal");

    assert!(
        err.to_string()
            .contains("non-contiguous finalized L1 block")
    );
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_parent_mismatch_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .try_enqueue(
            seal(make_chained_header(11, B256::with_last_byte(0xff))),
            L1PortalEvents::default(),
        )
        .expect_err("a finalized parent mismatch must be fatal");

    assert!(err.to_string().contains("finalized L1 parent mismatch"));
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_conflicting_tip_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let mut conflicting = make_test_header(10);
    conflicting.gas_limit += 1;
    let err = queue
        .try_enqueue(seal(conflicting), L1PortalEvents::default())
        .expect_err("a conflicting finalized tip must be fatal");

    assert!(err.to_string().contains("conflicting finalized L1 block"));
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_stale_blocks() {
    let mut queue = PendingDeposits::default();
    queue.enqueue(make_test_header(10), L1PortalEvents::default());

    let err = queue
        .try_enqueue(seal(make_test_header(9)), L1PortalEvents::default())
        .expect_err("an out-of-order finalized block must be fatal");

    assert!(err.to_string().contains("out-of-order finalized L1 block"));
    assert_eq!(queue.pending_len(), 1);
}

#[test]
fn finalized_queue_rejects_confirmation_mismatch_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .confirm(NumHash::new(10, B256::with_last_byte(0xff)))
        .expect_err("confirming a different block must fail");

    assert!(
        err.to_string()
            .contains("finalized L1 queue confirmation mismatch")
    );
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(
        queue
            .peek()
            .expect("front should remain queued")
            .header
            .hash(),
        h10_hash
    );
}

fn confirm_shared(queue: &DepositQueue) -> L1BlockDeposits {
    let num_hash = queue.peek().expect("queue is empty").header.num_hash();
    queue.confirm(num_hash).expect("confirm mismatch")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositHashFixture {
    previous_hash: String,
    expected_hash: String,
    single_value_tuple_hash: String,
    deposit: DepositFixture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositFixture {
    token: String,
    sender: String,
    amount: u128,
    arc_refund_recipient: String,
    key_index: u64,
    encrypted: DepositPayloadFixture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositPayloadFixture {
    ephemeral_pubkey_x: String,
    ephemeral_pubkey_y_parity: u8,
    ciphertext: String,
    nonce: String,
    tag: String,
}

fn deposit_hash_fixture() -> DepositHashFixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/depositHashChain.json"
    )))
    .expect("deposit hash fixture JSON should decode")
}

fn parse_fixture_address(value: &str) -> Address {
    value
        .parse()
        .unwrap_or_else(|err| panic!("invalid fixture address {value}: {err}"))
}

fn parse_fixture_b256(value: &str) -> B256 {
    value
        .parse()
        .unwrap_or_else(|err| panic!("invalid fixture bytes32 {value}: {err}"))
}

fn parse_fixture_hex(value: &str) -> Vec<u8> {
    const_hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .unwrap_or_else(|err| panic!("invalid fixture hex {value}: {err}"))
}

fn parse_fixture_fixed<const N: usize>(value: &str, name: &str) -> [u8; N] {
    let bytes = parse_fixture_hex(value);
    assert_eq!(bytes.len(), N, "fixture field {name} should be {N} bytes");
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    out
}

impl DepositFixture {
    fn to_l1_deposit(&self) -> Deposit {
        Deposit {
            token: parse_fixture_address(&self.token),
            sender: parse_fixture_address(&self.sender),
            amount: self.amount,
            fee: 0,
            arc_refund_recipient: parse_fixture_address(&self.arc_refund_recipient),
            key_index: U256::from(self.key_index),
            ephemeral_pubkey_x: parse_fixture_b256(&self.encrypted.ephemeral_pubkey_x),
            ephemeral_pubkey_y_parity: self.encrypted.ephemeral_pubkey_y_parity,
            ciphertext: parse_fixture_hex(&self.encrypted.ciphertext),
            nonce: parse_fixture_fixed(&self.encrypted.nonce, "encrypted.nonce"),
            tag: parse_fixture_fixed(&self.encrypted.tag, "encrypted.tag"),
        }
    }
}

fn deposit_hash_chain(previous_hash: B256, deposits: &[L1Deposit]) -> B256 {
    deposits.iter().fold(previous_hash, |current, deposit| {
        deposit.hash_chain(current)
    })
}

#[test]
fn test_deposit_hash_chain() {
    let fixture = deposit_hash_fixture();
    let encrypted = fixture.deposit.to_l1_deposit();
    let previous_hash = parse_fixture_b256(&fixture.previous_hash);

    let next_hash = deposit_hash_chain(previous_hash, &[L1Deposit::Deposit(encrypted.clone())]);

    let abi_deposit = abi::Deposit {
        token: encrypted.token,
        sender: encrypted.sender,
        amount: encrypted.amount,
        arcRefundRecipient: encrypted.arc_refund_recipient,
        keyIndex: encrypted.key_index,
        encrypted: abi::DepositPayload {
            ephemeralPubkeyX: encrypted.ephemeral_pubkey_x,
            ephemeralPubkeyYParity: encrypted.ephemeral_pubkey_y_parity,
            ciphertext: encrypted.ciphertext.clone().into(),
            nonce: encrypted.nonce.into(),
            tag: encrypted.tag.into(),
        },
    };
    let expected = parse_fixture_b256(&fixture.expected_hash);
    let tuple_value_hash =
        keccak256((DepositType::Deposit, abi_deposit, previous_hash).abi_encode());
    let single_value_tuple_hash = parse_fixture_b256(&fixture.single_value_tuple_hash);

    assert_eq!(
        next_hash, expected,
        "deposit hash chain must match Solidity DepositQueueLib.enqueueDeposit"
    );
    assert_eq!(
        tuple_value_hash, single_value_tuple_hash,
        "fixture should document the previous single-value tuple encoding"
    );
    assert_ne!(
        expected, tuple_value_hash,
        "single-value tuple encoding should not match Solidity abi.encode(...) for dynamic deposits"
    );
    assert_ne!(next_hash, B256::ZERO, "hash should be non-zero");
}

#[test]
fn test_withdrawal_bounce_back_and_deposit_hash_chain() {
    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001111");
    let recipient = address!("0x000000000000000000000000000000000000A11C");

    let bounce_back = WithdrawalBounceBackDeposit {
        token,
        to: recipient,
        amount: 500_000,
        fee: 0,
    };

    let encrypted = Deposit {
        token,
        sender,
        amount: 300_000,
        fee: 0,
        arc_refund_recipient: sender,
        key_index: U256::ONE,
        ephemeral_pubkey_x: B256::with_last_byte(0xBB),
        ephemeral_pubkey_y_parity: 0x03,
        ciphertext: vec![0x55u8; 64],
        nonce: [0x0A; 12],
        tag: [0x0B; 16],
    };

    let deposits = vec![
        L1Deposit::WithdrawalBounceBack(bounce_back.clone()),
        L1Deposit::Deposit(encrypted.clone()),
    ];

    let next_hash = deposit_hash_chain(B256::ZERO, &deposits);

    // Manually compute expected chain
    let hash_1 = keccak256(
        (
            DepositType::WithdrawalBounceBack,
            abi::WithdrawalBounceBackDeposit {
                token: bounce_back.token,
                to: bounce_back.to,
                amount: bounce_back.amount,
            },
            B256::ZERO,
        )
            .abi_encode_params(),
    );

    let hash_2 = keccak256(
        (
            DepositType::Deposit,
            abi::Deposit {
                token: encrypted.token,
                sender: encrypted.sender,
                amount: encrypted.amount,
                arcRefundRecipient: encrypted.arc_refund_recipient,
                keyIndex: encrypted.key_index,
                encrypted: abi::DepositPayload {
                    ephemeralPubkeyX: encrypted.ephemeral_pubkey_x,
                    ephemeralPubkeyYParity: encrypted.ephemeral_pubkey_y_parity,
                    ciphertext: encrypted.ciphertext.into(),
                    nonce: encrypted.nonce.into(),
                    tag: encrypted.tag.into(),
                },
            },
            hash_1,
        )
            .abi_encode_params(),
    );

    assert_eq!(next_hash, hash_2);
}

#[test]
fn observed_portal_events_require_complete_advance_arc_inputs() {
    let events = L1PortalEvents {
        deposits: vec![
            make_withdrawal_bounce_back(100),
            make_withdrawal_bounce_back(200),
        ],
        enabled_tokens: vec![EnabledToken {
            token: abi::SPHERE_TOKEN_ADDRESS,
            name: "Alpha USD".to_owned(),
            symbol: "aUSD".to_owned(),
            currency: "USD".to_owned(),
        }],
        encryption_key_rotations: vec![],
        leader_transitions: vec![],
        portal_pause: None,
    };
    let deposits: Vec<_> = events
        .deposits
        .iter()
        .map(L1Deposit::to_abi_queued_deposit)
        .collect();
    let enabled_tokens: Vec<_> = events
        .enabled_tokens
        .iter()
        .map(EnabledToken::to_abi)
        .collect();

    // Rejection is a sequencer decision and does not change the authenticated deposit identity.
    events
        .validate_advance_arc_inputs(&deposits, &enabled_tokens)
        .unwrap();

    let partial = events
        .validate_advance_arc_inputs(&deposits[..1], &enabled_tokens)
        .unwrap_err();
    assert!(partial.to_string().contains("deposit count"));

    let mut fabricated = deposits.clone();
    fabricated[1].depositData = Bytes::from_static(b"fabricated");
    let fabricated = events
        .validate_advance_arc_inputs(&fabricated, &enabled_tokens)
        .unwrap_err();
    assert!(fabricated.to_string().contains("deposit 1"));

    let missing_token = events
        .validate_advance_arc_inputs(&deposits, &[])
        .unwrap_err();
    assert!(missing_token.to_string().contains("token enables"));
}

#[test]
fn test_push_log_decodes_withdrawal_bounce_back() {
    let portal_address = address!("0x0000000000000000000000000000000000000ABC");
    let fallback_nonce = 0xF1;
    let encoded_fallback_nonce = Address::with_last_byte(0xf1);
    let token = address!("0x0000000000000000000000000000000000002000");
    let event = WithdrawalBounceBack {
        newCurrentDepositQueueHash: B256::with_last_byte(0x42),
        fallbackNonce: fallback_nonce,
        token,
        amount: 123_456,
        depositNumber: 1,
    };
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal_address,
            data: event.encode_log_data(),
        },
        block_hash: None,
        block_number: None,
        block_timestamp: None,
        transaction_hash: None,
        transaction_index: None,
        log_index: None,
        removed: false,
    };

    let mut events = L1PortalEvents::default();
    events
        .push_log(&log, 123)
        .expect("bounce-back should decode");

    assert_eq!(events.deposits.len(), 1, "should enqueue one deposit");
    let L1Deposit::WithdrawalBounceBack(deposit) = &events.deposits[0] else {
        panic!("bounce-back should be mapped to a withdrawal bounce-back entry");
    };
    assert_eq!(deposit.token, token);
    assert_eq!(deposit.to, encoded_fallback_nonce);
    assert_eq!(deposit.amount, event.amount);
    assert_eq!(deposit.fee, 0, "bounce-back deposits should be fee-free");
}

#[test]
fn test_drain_returns_block_grouped_deposits() {
    let mut queue = PendingDeposits::default();

    let d1 = L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount: 100,
        fee: 0,
    });

    let d2 = L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(4),
        amount: 200,
        fee: 0,
    });

    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::from_deposits(vec![d1]));
    queue.enqueue(
        make_chained_header(11, h10_hash),
        L1PortalEvents::from_deposits(vec![d2]),
    );

    let blocks = queue.drain();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].header.number(), 10);
    assert_eq!(blocks[0].events.deposits.len(), 1);
    assert_eq!(blocks[1].header.number(), 11);
    assert_eq!(blocks[1].events.deposits.len(), 1);

    // After drain, pending is empty
    assert!(queue.drain().is_empty());
}

#[tokio::test]
async fn test_prepare_decrypted_deposit_defers_policy_to_upstream_mint() {
    use k256::{AffinePoint, ProjectivePoint, Scalar};

    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x000000000000000000000000000000000000BEEF");
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let block_number = 10;

    let sequencer_key = k256::SecretKey::from_slice(&[0x11; 32]).expect("valid key");
    let seq_scalar: Scalar = *sequencer_key.to_nonzero_scalar();
    let seq_pub = AffinePoint::from(ProjectivePoint::GENERATOR * seq_scalar);
    let (seq_pub_x, seq_pub_y_parity) =
        crate::precompiles::ecies::compressed_x_and_parity(&seq_pub);
    let encrypted = crate::precompiles::ecies::encrypt_deposit(
        &seq_pub_x,
        seq_pub_y_parity,
        recipient,
        B256::ZERO,
        sender,
        portal,
        U256::ZERO,
    )
    .expect("encrypted deposit should be valid");
    let encryption_keys = EncryptionKeyRing::new([sequencer_key.clone()]);
    encryption_keys
        .apply_rotation(&EncryptionKeyRotation {
            x: seq_pub_x,
            y_parity: seq_pub_y_parity,
            pubkey: encryption_key_address(seq_pub_x, seq_pub_y_parity).unwrap(),
            key_index: U256::ZERO,
            activation_block: block_number,
        })
        .unwrap();

    let block = L1BlockDeposits {
        header: seal(make_test_header(block_number)),
        events: L1PortalEvents::from_deposits(vec![L1Deposit::Deposit(Deposit {
            token,
            sender,
            amount: 1_000_000,
            fee: 0,
            arc_refund_recipient: sender,
            key_index: U256::ZERO,
            ephemeral_pubkey_x: encrypted.eph_pub_x,
            ephemeral_pubkey_y_parity: encrypted.eph_pub_y_parity,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
        })]),
    };

    let prepared = block
        .prepare(&encryption_keys, portal)
        .await
        .expect("decrypted deposit should prepare without an engine-side policy read");

    assert_eq!(prepared.queued_deposits.len(), 1);
    assert_eq!(
        prepared.queued_deposits[0].depositType,
        DepositType::Deposit
    );
    assert_eq!(
        prepared.decryptions.len(),
        1,
        "successfully decrypted deposits must provide on-chain decryption data"
    );
}

#[tokio::test]
async fn deposits_select_the_private_key_by_portal_index() {
    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001234");
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let old = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let current = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
    let encryption_keys = EncryptionKeyRing::new([old.clone(), current.clone()]);
    let mut deposits = Vec::new();
    let mut expected_shared_secrets = Vec::new();

    for (key_index, key, recipient) in [
        (
            U256::ZERO,
            old,
            address!("0x000000000000000000000000000000000000BEEF"),
        ),
        (
            U256::ONE,
            current,
            address!("0x000000000000000000000000000000000000CAFE"),
        ),
    ] {
        let public = key.public_key();
        let (x, y_parity) = crate::precompiles::ecies::compressed_x_and_parity(public.as_affine());
        encryption_keys
            .apply_rotation(&EncryptionKeyRotation {
                x,
                y_parity,
                pubkey: encryption_key_address(x, y_parity).unwrap(),
                key_index,
                activation_block: key_index.to::<u64>() + 10,
            })
            .unwrap();
        let encrypted = crate::precompiles::ecies::encrypt_deposit(
            &x,
            y_parity,
            recipient,
            B256::ZERO,
            sender,
            portal,
            key_index,
        )
        .unwrap();
        let decrypted = crate::precompiles::ecies::decrypt_deposit(
            &key,
            &encrypted.eph_pub_x,
            encrypted.eph_pub_y_parity,
            &encrypted.ciphertext,
            &encrypted.nonce,
            &encrypted.tag,
            portal,
            key_index,
            sender,
        )
        .unwrap();
        expected_shared_secrets.push(decrypted.proof.shared_secret);
        deposits.push(L1Deposit::Deposit(Deposit {
            token,
            sender,
            amount: 1_000_000,
            fee: 0,
            arc_refund_recipient: sender,
            key_index,
            ephemeral_pubkey_x: encrypted.eph_pub_x,
            ephemeral_pubkey_y_parity: encrypted.eph_pub_y_parity,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
        }));
    }

    let prepared = L1BlockDeposits {
        header: seal(make_test_header(20)),
        events: L1PortalEvents::from_deposits(deposits),
    }
    .prepare(&encryption_keys, portal)
    .await
    .unwrap();

    assert_eq!(
        prepared
            .decryptions
            .iter()
            .map(|decryption| decryption.sharedSecret)
            .collect::<Vec<_>>(),
        expected_shared_secrets
    );
}

fn leader_updated_log(
    portal: Address,
    previous: Address,
    new_leader: Address,
    epoch: u64,
    activation: u64,
) -> Log {
    let event = crate::abi::SpherePortal::LeaderUpdated {
        previousLeader: previous,
        newLeader: new_leader,
        epoch,
        activationArcBlock: activation,
    };
    Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        ..Default::default()
    }
}

fn encryption_key_updated_log(
    portal: Address,
    x: B256,
    y_parity: u8,
    pubkey: Address,
    key_index: U256,
    activation_block: u64,
) -> Log {
    let event = crate::abi::SpherePortal::SequencerEncryptionKeyUpdated {
        x,
        yParity: y_parity,
        pubkey,
        keyIndex: key_index,
        activationBlock: activation_block,
    };
    Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        ..Default::default()
    }
}

#[test]
fn encryption_key_event_binds_private_key_to_portal_index() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let private_key = k256::SecretKey::from_slice(&[0x42; 32]).unwrap();
    let public_key = private_key.public_key();
    let (x, y_parity) = crate::precompiles::ecies::compressed_x_and_parity(public_key.as_affine());
    let pubkey = encryption_key_address(x, y_parity).unwrap();
    let key_index = U256::from(7);
    let mut events = L1PortalEvents::default();

    events
        .push_log(
            &encryption_key_updated_log(portal, x, y_parity, pubkey, key_index, 77),
            77,
        )
        .unwrap();

    assert_eq!(
        events.encryption_key_rotations,
        vec![EncryptionKeyRotation {
            x,
            y_parity,
            pubkey,
            key_index,
            activation_block: 77,
        }]
    );

    let ring = EncryptionKeyRing::new([private_key.clone()]);
    ring.apply_rotation(&events.encryption_key_rotations[0])
        .unwrap();
    assert_eq!(
        ring.key(key_index).unwrap().to_bytes(),
        private_key.to_bytes()
    );
}

#[test]
fn decodes_leader_updated_into_portal_events() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let previous = address!("0x0000000000000000000000000000000000001111");
    let new_leader = address!("0x0000000000000000000000000000000000002222");

    let mut events = L1PortalEvents::default();
    events
        .push_log(&leader_updated_log(portal, previous, new_leader, 4, 77), 77)
        .unwrap();

    assert_eq!(
        events.leader_transitions,
        vec![LeaderTransition {
            previous_leader: previous,
            new_leader,
            epoch: 4,
            activation_arc_block: 77,
        }]
    );
    let transition = events.final_leader_transition().unwrap().unwrap();
    assert_eq!(transition.new_leader, new_leader);
    assert_eq!(transition.epoch, 4);
}

#[test]
fn rejects_multiple_leader_transitions_in_one_block() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let a = address!("0x0000000000000000000000000000000000001111");
    let b = address!("0x0000000000000000000000000000000000002222");
    let c = address!("0x0000000000000000000000000000000000003333");

    let mut events = L1PortalEvents::default();
    events
        .push_log(&leader_updated_log(portal, a, b, 4, 77), 77)
        .unwrap();
    events
        .push_log(&leader_updated_log(portal, b, c, 5, 77), 77)
        .unwrap();

    let err = events.final_leader_transition().unwrap_err();
    assert!(err.to_string().contains("at most one"));
}

fn set_arc_checkpoint(provider: &MockEthProvider, checkpoint: NumHash) {
    provider.add_account(
        crate::abi::ARC_STATE_ADDRESS,
        ExtendedAccount::new(0, U256::ZERO).extend_storage([
            (
                crate::precompiles::arc_state::slots::ARC_BLOCK_NUMBER.into(),
                U256::from(checkpoint.number),
            ),
            (
                crate::precompiles::arc_state::slots::ARC_BLOCK_HASH.into(),
                checkpoint.hash.into(),
            ),
        ]),
    );
}

fn test_subscriber_with_checkpoint(checkpoint: NumHash) -> L1Subscriber<MockEthProvider> {
    let portal_address = address!("0x0000000000000000000000000000000000000ABC");
    let sphere_provider = MockEthProvider::new();
    set_arc_checkpoint(&sphere_provider, checkpoint);

    L1Subscriber {
        config: L1SubscriberConfig {
            l1_rpc_url: "http://127.0.0.1:8545".to_owned(),
            portal_address,
            l1_fetch_concurrency: 1,
            retry_connection_interval: Duration::from_secs(1),
            retain_portal_evidence: false,
            deferred_work_start: None,
        },
        sphere_provider,
        deposit_queue: DepositQueue::default(),
        enabled_tokens: crate::state::EnabledTokenRegistry::default(),
        l1_state_cache: crate::L1StateCache::new(),
        block_tracker: L1BlockTracker::default(),
        leadership_sink: None,
        finalized_batch_submissions: None,
        encryption_keys: None,
        subscriber_metrics: Default::default(),
    }
}

fn test_subscriber(block_number: u64) -> L1Subscriber<MockEthProvider> {
    test_subscriber_with_checkpoint(NumHash::new(block_number, B256::with_last_byte(1)))
}
#[test]
fn test_resolve_start_block_reads_live_local_state_each_time() {
    let subscriber = test_subscriber(10);
    assert_eq!(subscriber.resolve_start_block().unwrap(), 11);
    set_arc_checkpoint(
        &subscriber.sphere_provider,
        NumHash::new(11, B256::with_last_byte(1)),
    );
    assert_eq!(subscriber.resolve_start_block().unwrap(), 12);
}

#[test]
fn test_resolve_start_block_accepts_block_zero_with_nonzero_hash() {
    let subscriber = test_subscriber(0);
    assert_eq!(subscriber.resolve_start_block().unwrap(), 1);
}

#[test]
fn test_resolve_start_block_rejects_unanchored_genesis() {
    let subscriber = test_subscriber_with_checkpoint(NumHash::default());
    assert!(
        subscriber
            .resolve_start_block()
            .unwrap_err()
            .to_string()
            .contains("sphere genesis is not anchored to an L1 block")
    );
}

fn push_header_and_empty_receipts(asserter: &Asserter, header: Header) {
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header)));
    asserter.push_success(&Some(Vec::<TransactionReceipt>::new()));
}

#[tokio::test]
async fn test_follow_finalized_uses_new_heads_to_sync_missing_finalized_range() {
    let subscriber = test_subscriber(9);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<Ethereum>().connect_mocked_client(asserter.clone());

    let header_10 = make_test_header(10);
    let header_11 = make_chained_header(11, header_10.hash_slow());
    let header_12 = make_chained_header(12, header_11.hash_slow());
    let anchor_12 = seal(header_12.clone()).num_hash();

    // Initial sync through finalized block 10.
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_10.clone())));
    push_header_and_empty_receipts(&asserter, header_10);
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(make_test_header(10))));

    // One newHeads notification wakes the subscriber. The finalized tag has
    // advanced by two blocks, so both missing blocks must be ingested.
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_12.clone())));
    push_header_and_empty_receipts(&asserter, header_11);
    push_header_and_empty_receipts(&asserter, header_12.clone());
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_12)));

    let err = subscriber
        .follow_finalized(&l1_provider, Box::pin(futures::stream::iter([()])))
        .await
        .expect_err("finite header stream should end the subscriber");
    assert!(err.to_string().contains("head notification stream ended"));

    let blocks = subscriber.deposit_queue.drain();
    assert_eq!(
        blocks
            .iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![10, 11, 12]
    );
    assert_eq!(
        subscriber.block_tracker.observed_hash(12),
        Some(anchor_12.hash),
        "a queue-backed subscriber must retain observations until its consumer prunes them"
    );
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_subscribe_block_headers_falls_back_to_http_block_filter() {
    let subscriber = test_subscriber(10);
    let asserter = Asserter::new();
    let l1_provider = ProviderBuilder::new_with_network::<Ethereum>()
        .connect_mocked_client(asserter.clone())
        .erased();

    asserter.push_success(&U256::ONE);
    asserter.push_success(&vec![B256::with_last_byte(1)]);

    let mut header_stream = subscriber
        .subscribe_block_headers(&l1_provider)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), header_stream.next())
        .await
        .expect("HTTP block filter should emit a header notification")
        .expect("HTTP block filter stream should remain open");

    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_sync_finalized_once_does_not_refetch_current_cursor() {
    let subscriber = test_subscriber(10);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<Ethereum>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(make_test_header(10))));
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(make_test_header(10))));

    let next = subscriber
        .sync_to_finalized(&l1_provider, 11)
        .await
        .unwrap();

    assert_eq!(next, 11);
    assert_eq!(
        subscriber.block_tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 10,
            ready: true,
        })
    );
    assert!(subscriber.deposit_queue.drain().is_empty());
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_sync_finalized_once_extends_a_moving_finalized_target_until_stable() {
    let subscriber = test_subscriber(9);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<Ethereum>().connect_mocked_client(asserter.clone());

    let header_10 = make_test_header(10);
    let header_11 = make_chained_header(11, header_10.hash_slow());
    let header_12 = make_chained_header(12, header_11.hash_slow());

    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_10.clone())));
    push_header_and_empty_receipts(&asserter, header_10);
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_12.clone())));
    push_header_and_empty_receipts(&asserter, header_11);
    push_header_and_empty_receipts(&asserter, header_12.clone());
    asserter.push_success(&Some(alloy_rpc_types_eth::Header::new(header_12)));

    let next = subscriber
        .sync_to_finalized(&l1_provider, 10)
        .await
        .unwrap();

    assert_eq!(next, 13);
    assert_eq!(
        subscriber
            .deposit_queue
            .drain()
            .iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![10, 11, 12]
    );
    assert_eq!(
        subscriber.block_tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 12,
            ready: true,
        })
    );
    assert!(asserter.read_q().is_empty());
}

