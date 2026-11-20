pub mod slots {
    use alloy_primitives::U256;

    pub const WITHDRAWAL_QUEUE_HASH: U256 = U256::from_limbs([1, 0, 0, 0]);
    pub const WITHDRAWAL_BATCH_INDEX: U256 = U256::from_limbs([2, 0, 0, 0]);
}
