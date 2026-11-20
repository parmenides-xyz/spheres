use super::SphereProtocolTx;
use alloy_consensus::Transaction;
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded, IntoTxEnv};
use alloy_primitives::{Address, Bytes};
use revm::context::TxEnv;
use sphere_primitives::envelope::{SphereTransactionKind, SphereTxEnvelope};

impl IntoTxEnv<Self> for SphereProtocolTx {
    fn into_tx_env(self) -> Self {
        self
    }
}

impl FromRecoveredTx<SphereTxEnvelope> for SphereProtocolTx {
    fn from_recovered_tx(tx: &SphereTxEnvelope, sender: Address) -> Self {
        let inner = match tx {
            SphereTxEnvelope::Legacy(tx) => TxEnv::from_recovered_tx(tx.tx(), sender),
            SphereTxEnvelope::Eip1559(tx) => TxEnv::from_recovered_tx(tx.tx(), sender),
            SphereTxEnvelope::Eip2930(tx) => TxEnv::from_recovered_tx(tx.tx(), sender),
            SphereTxEnvelope::Eip4844(tx) => TxEnv::from_recovered_tx(tx.tx(), sender),
            SphereTxEnvelope::Eip7702(tx) => TxEnv::from_recovered_tx(tx.tx(), sender),
        };
        Self {
            tx_hash: *alloy_consensus::transaction::TxHashRef::tx_hash(tx),
            inner,
            system: tx.is_system_tx().then(|| {
                (
                    SphereTransactionKind::classify(tx),
                    tx.is_valid_system_tx(tx.chain_id().unwrap_or_default()),
                )
            }),
        }
    }
}
impl FromTxWithEncoded<SphereTxEnvelope> for SphereProtocolTx {
    fn from_encoded_tx(tx: &SphereTxEnvelope, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

use alloy_primitives::{B256, TxKind, U256};
impl revm::context::Transaction for SphereProtocolTx {
    type AccessListItem<'a> = <TxEnv as revm::context::Transaction>::AccessListItem<'a>;
    type Authorization<'a> = <TxEnv as revm::context::Transaction>::Authorization<'a>;

    fn tx_type(&self) -> u8 {
        self.inner.tx_type
    }

    fn kind(&self) -> TxKind {
        self.inner.kind
    }

    fn caller(&self) -> Address {
        self.inner.caller
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit
    }

    fn gas_price(&self) -> u128 {
        self.inner.gas_price
    }

    fn value(&self) -> U256 {
        self.inner.value
    }

    fn nonce(&self) -> u64 {
        self.inner.nonce
    }

    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id
    }

    fn access_list(&self) -> Option<impl Iterator<Item = Self::AccessListItem<'_>>> {
        Some(self.inner.access_list.0.iter())
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.gas_price
    }

    fn max_fee_per_blob_gas(&self) -> u128 {
        self.inner.max_fee_per_blob_gas
    }

    fn authorization_list_len(&self) -> usize {
        self.inner.authorization_list.len()
    }

    fn authorization_list(&self) -> impl Iterator<Item = Self::Authorization<'_>> {
        self.inner.authorization_list.iter()
    }

    fn input(&self) -> &Bytes {
        &self.inner.data
    }

    fn blob_versioned_hashes(&self) -> &[B256] {
        &self.inner.blob_hashes
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.gas_priority_fee
    }
}
impl alloy_evm::TransactionEnvMut for SphereProtocolTx {
    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.inner.set_gas_limit(gas_limit);
    }
    fn set_nonce(&mut self, nonce: u64) {
        self.inner.set_nonce(nonce);
    }
    fn set_access_list(&mut self, access_list: alloy_eips::eip2930::AccessList) {
        self.inner.set_access_list(access_list);
    }
}

impl<Spec, Block: alloy_evm::env::BlockEnvironment>
    alloy_evm::rpc::TryIntoTxEnv<SphereProtocolTx, Spec, Block>
    for alloy_rpc_types_eth::TransactionRequest
{
    type Err = alloy_evm::rpc::EthTxEnvError;

    fn try_into_tx_env(
        self,
        evm_env: &alloy_evm::EvmEnv<Spec, Block>,
    ) -> Result<SphereProtocolTx, Self::Err> {
        let inner: TxEnv = self.try_into_tx_env(evm_env)?;
        Ok(SphereProtocolTx {
            inner,
            tx_hash: B256::repeat_byte(0xff),
            system: None,
        })
    }
}
