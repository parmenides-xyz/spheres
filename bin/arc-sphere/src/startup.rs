use alloy_consensus::TxReceipt;
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_sol_types::SolEvent;
use k256::SecretKey;
use reth_provider::{BlockNumReader, ReceiptProvider, StateProviderFactory};
use sphere_contracts::{ArcAdvanced, LegacyArcAdvanced, SPHERE_INBOX_ADDRESS, SpherePortal};
use sphere_l1::{ArcStateExt, EncryptionKeyRing, EncryptionKeyRotation, encryption_key_address};
use sphere_payload::WithdrawalRevealEncryptor;
use std::sync::Arc;

pub fn latest_operational_arc_block<P>(provider: &P) -> eyre::Result<u64>
where
    P: BlockNumReader + ReceiptProvider + StateProviderFactory,
{
    let best = provider.best_block_number()?;
    for number in (1..=best).rev() {
        let Some(receipts) = provider.receipts_by_block(BlockHashOrNumber::Number(number))? else {
            continue;
        };
        for receipt in receipts {
            for log in receipt.logs() {
                if log.address != SPHERE_INBOX_ADDRESS {
                    continue;
                }
                match log.topics().first() {
                    Some(topic) if topic == &ArcAdvanced::SIGNATURE_HASH => {
                        return Ok(ArcAdvanced::decode_log(log)?.arcBlockNumber);
                    }
                    Some(topic) if topic == &LegacyArcAdvanced::SIGNATURE_HASH => {
                        return Ok(LegacyArcAdvanced::decode_log(log)?.arcBlockNumber);
                    }
                    _ => {}
                }
            }
        }
    }

    let genesis_hash = provider
        .block_hash(0)?
        .ok_or_else(|| eyre::eyre!("sphere genesis block hash is unavailable"))?;
    Ok(provider
        .state_by_block_hash(genesis_hash)?
        .arc_num_hash()?
        .number)
}

pub async fn resolve_and_seed_encryption_keys(
    portal_address: Address,
    deferred_work_start: Option<u64>,
    l1_provider: &alloy_provider::DynProvider<alloy_provider::network::Ethereum>,
    block_number: u64,
    keys: &EncryptionKeyRing,
) -> eyre::Result<()> {
    // Synthetic-L1 nodes use the zero address to mean that no Portal is configured.
    if portal_address.is_zero() {
        return Ok(());
    }

    let block_id = alloy_rpc_types_eth::BlockId::number(block_number);
    let portal_code = l1_provider
        .get_code_at(portal_address)
        .block_id(block_id)
        .await?;
    if portal_code.is_empty() {
        return Ok(());
    }

    let portal = SpherePortal::new(portal_address, l1_provider);
    let count = portal.encryptionKeyCount().block(block_id).call().await?;
    let count: u64 = count
        .try_into()
        .map_err(|_| eyre::eyre!("Portal encryption key count does not fit in u64"))?;

    for index in 0..count {
        let key_index = U256::from(index);
        let entry = portal
            .encryptionKeyAt(key_index)
            .block(block_id)
            .call()
            .await?;
        let rotation = EncryptionKeyRotation {
            x: entry.x,
            y_parity: entry.yParity,
            pubkey: encryption_key_address(entry.x, entry.yParity)?,
            key_index,
            activation_block: entry.activationBlock,
        };
        if keys.has_candidate(rotation.x, rotation.y_parity) {
            keys.apply_rotation(&rotation)?;
            continue;
        }

        let validity = portal
            .isEncryptionKeyValid(key_index)
            .block(block_id)
            .call()
            .await?;
        eyre::ensure!(
            !validity.valid
                // A key that has expired at the persisted checkpoint may still be needed by a deposit in the
                // deferred Portal-work range.
                    && deferred_work_start.is_none_or(|from| validity.expiresAtBlock <= from),
            "missing private decryption key for Portal key index {key_index} required at L1 \
                 checkpoint {block_number} or by deferred work starting at {:?} (expires at L1 \
                 block {})",
            deferred_work_start,
            validity.expiresAtBlock,
        );
    }

    Ok(())
}

/// Sequencer-side sender reveal encryptor used while building
/// `finalizeWithdrawalBatch` system transactions.
///
/// The encrypted sender payload is hashed into withdrawal data, so ECIES must
/// not use fresh randomness here. This implementation derives reproducible
/// encryption material from the sequencer encryption key, sphere id, reveal key,
/// sender, withdrawal transaction hash, and fallback nonce, which keeps identical
/// withdrawal batches byte-for-byte stable across sequencers.
pub struct SequencerWithdrawalRevealEncryptor {
    encryption_key: Arc<SecretKey>,
    sphere_id: u32,
}

impl SequencerWithdrawalRevealEncryptor {
    pub fn new(encryption_key: SecretKey, sphere_id: u32) -> Self {
        Self {
            encryption_key: Arc::new(encryption_key),
            sphere_id,
        }
    }
}

impl std::fmt::Debug for SequencerWithdrawalRevealEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequencerWithdrawalRevealEncryptor")
            .field("sphere_id", &self.sphere_id)
            .finish_non_exhaustive()
    }
}

impl WithdrawalRevealEncryptor for SequencerWithdrawalRevealEncryptor {
    fn encrypt_sender(
        &self,
        reveal_to: &[u8],
        sender: Address,
        tx_hash: alloy_primitives::B256,
        fallback_nonce: u64,
    ) -> Option<Vec<u8>> {
        sphere_precompiles::ecies::encrypt_authenticated_withdrawal_deterministic(
            &self.encryption_key,
            self.sphere_id,
            reveal_to,
            sender,
            tx_hash,
            fallback_nonce,
        )
    }
}
