use alloy_consensus::{Typed2718, error::ValueError, transaction::TxHashRef};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2930::AccessList,
    eip4844::{BlobTransactionValidationError, env_settings::KzgSettings},
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256};
use reth_ethereum_primitives::PooledTransactionVariant;
use reth_primitives_traits::{InMemorySize, Recovered};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};
use sphere_primitives::envelope::SphereTxEnvelope;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SpherePooledTransaction {
    inner: EthPooledTransaction<SphereTxEnvelope>,
}

impl PoolTransaction for SpherePooledTransaction {
    type TryFromConsensusError = ValueError<SphereTxEnvelope>;

    type Consensus = SphereTxEnvelope;

    type Pooled = PooledTransactionVariant;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction().clone()
    }

    fn consensus_ref(&self) -> Recovered<&Self::Consensus> {
        Recovered::new_unchecked(&*self.inner.transaction, self.inner.transaction.signer())
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_length = tx.encode_2718_len();
        let (tx, signer) = tx.into_parts();
        let transaction = Recovered::new_unchecked(tx.into(), signer);
        Self {
            inner: EthPooledTransaction::new(transaction, encoded_length),
        }
    }

    /// Returns hash of the transaction.
    fn hash(&self) -> &TxHash {
        self.inner.transaction.tx_hash()
    }

    /// Returns the Sender of the transaction.
    fn sender(&self) -> Address {
        self.inner.transaction.signer()
    }

    /// Returns a reference to the Sender of the transaction.
    fn sender_ref(&self) -> &Address {
        self.inner.transaction.signer_ref()
    }

    /// Returns the cost that this transaction is allowed to consume:
    ///
    /// For EIP-1559 transactions: `max_fee_per_gas * gas_limit + tx_value`.
    /// For legacy transactions: `gas_price * gas_limit + tx_value`.
    /// For EIP-4844 blob transactions: `max_fee_per_gas * gas_limit + tx_value +
    /// max_blob_fee_per_gas * blob_gas_used`.
    fn cost(&self) -> &U256 {
        &self.inner.cost
    }

    /// Returns the length of the rlp encoded object
    fn encoded_length(&self) -> usize {
        self.inner.encoded_length
    }
}

impl Typed2718 for SpherePooledTransaction {
    fn ty(&self) -> u8 {
        self.inner.transaction.ty()
    }
}

impl InMemorySize for SpherePooledTransaction {
    fn size(&self) -> usize {
        self.inner.transaction.size()
    }
}

impl alloy_consensus::Transaction for SpherePooledTransaction {
    fn chain_id(&self) -> Option<alloy_primitives::ChainId> {
        self.inner.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.inner.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.inner.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.inner.transaction.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.inner.transaction.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.transaction.is_create()
    }

    fn value(&self) -> U256 {
        self.inner.transaction.value()
    }

    fn input(&self) -> &Bytes {
        self.inner.transaction.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.transaction.authorization_list()
    }
}

impl EthPoolTransaction for SpherePooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecarVariant,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(
            self.ty(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxLegacy, transaction::SignerRecoverable};
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::Signature;
    use sphere_primitives::envelope::SPHERE_SYSTEM_TX_SIGNATURE;

    #[test]
    fn ordinary_transaction_preserves_signed_bytes_and_cost() {
        let transaction = TxLegacy {
            gas_price: 10,
            gas_limit: 1000,
            value: U256::from(100),
            ..Default::default()
        };
        let signed = SphereTxEnvelope::Legacy(transaction.into_signed(Signature::test_signature()));
        let raw = signed.encoded_2718();
        let wire = PooledTransactionVariant::decode_2718_exact(&raw).unwrap();
        let pooled = SpherePooledTransaction::from_pooled(wire.try_into_recovered().unwrap());
        assert_eq!(pooled.cost(), &U256::from(10100));
        assert_eq!(pooled.encoded_length(), raw.len());
        assert_eq!(pooled.sender(), signed.recover_signer().unwrap());
        assert_eq!(pooled.clone_into_pooled().unwrap().encoded_2718(), raw);
        assert_eq!(pooled.into_consensus().encoded_2718(), raw);
    }

    #[test]
    fn system_signature_cannot_enter_the_pool() {
        let system =
            SphereTxEnvelope::Legacy(TxLegacy::default().into_signed(SPHERE_SYSTEM_TX_SIGNATURE));
        let raw = system.encoded_2718();
        let wire = PooledTransactionVariant::decode_2718_exact(&raw).unwrap();
        assert!(wire.try_into_recovered().is_err());
        assert!(
            SpherePooledTransaction::try_from_consensus(system.try_into_recovered().unwrap())
                .is_err()
        );
    }
}
