use alloy_sol_types::SolCall;
use sphere_contracts::spheres::{
    ISphereInbox, ISphereOutbox, SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS,
};
#[cfg(feature = "reth")]
mod codec;
mod ethereum;

use alloy_consensus::{Signed, Transaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy};
use alloy_primitives::{Address, B256, Signature, U256};
use core::fmt;

/// Fake signature for Sphere system transactions.
pub const SPHERE_SYSTEM_TX_SIGNATURE: Signature = Signature::new(U256::ZERO, U256::ZERO, false);

/// Fake sender for Sphere system transactions.
pub const SPHERE_SYSTEM_TX_SENDER: Address = Address::ZERO;

/// The Sphere [EIP-2718] Transaction Envelope.
///
/// # Note:
///
/// This enum distinguishes between tagged and untagged legacy transactions, as
/// the in-protocol merkle tree may commit to EITHER 0-prefixed or raw.
/// Therefore we must ensure that encoding returns the precise byte-array that
/// was decoded, preserving the presence or absence of the `TransactionType`
/// flag.
///
/// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
#[derive(Clone, Debug, alloy_consensus::TransactionEnvelope)]
#[envelope(
    tx_type_name = SphereTxType,
    typed = SphereTypedTransaction,
    arbitrary_cfg(any())
)]
pub enum SphereTxEnvelope {
    /// An untagged [`TxLegacy`].
    #[envelope(ty = 0)]
    Legacy(Signed<TxLegacy>),
    /// A [`TxEip2930`] tagged with type 1.
    #[envelope(ty = 1)]
    Eip2930(Signed<TxEip2930>),
    /// A [`TxEip1559`] tagged with type 2.
    #[envelope(ty = 2)]
    Eip1559(Signed<TxEip1559>),
    /// A TxEip4844 tagged with type 3.
    /// An EIP-4844 transaction has two network representations:
    /// 1 - The transaction itself, which is a regular RLP-encoded transaction and used to retrieve
    /// historical transactions..
    ///
    /// 2 - The transaction with a sidecar, which is the form used to
    /// send transactions to the network.
    #[envelope(ty = 3)]
    Eip4844(Signed<TxEip4844>),
    /// A [`TxEip7702`] tagged with type 4.
    #[envelope(ty = 4)]
    Eip7702(Signed<TxEip7702>),
}

impl SphereTxEnvelope {
    /// Returns true if this is a Sphere system transaction
    pub fn is_system_tx(&self) -> bool {
        matches!(self, Self::Legacy(tx) if tx.signature() == &SPHERE_SYSTEM_TX_SIGNATURE)
    }

    /// Returns true if this is a valid Sphere system transaction, i.e all gas fields and nonce are zero.
    pub fn is_valid_system_tx(&self, chain_id: u64) -> bool {
        self.max_fee_per_gas() == 0
            && self.gas_limit() == 0
            && self.value().is_zero()
            && self.chain_id() == Some(chain_id)
            && self.nonce() == 0
    }
}

impl alloy_consensus::transaction::SignerRecoverable for SphereTxEnvelope {
    fn recover_signer(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Legacy(tx) if tx.signature() == &SPHERE_SYSTEM_TX_SIGNATURE => Ok(Address::ZERO),
            Self::Legacy(tx) => alloy_consensus::transaction::SignerRecoverable::recover_signer(tx),
            Self::Eip2930(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::Eip1559(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::Eip7702(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
            Self::Eip4844(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer(tx)
            }
        }
    }

    fn recover_signer_unchecked(
        &self,
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Legacy(tx) if tx.signature() == &SPHERE_SYSTEM_TX_SIGNATURE => Ok(Address::ZERO),
            Self::Legacy(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip2930(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip1559(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip7702(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
            Self::Eip4844(tx) => {
                alloy_consensus::transaction::SignerRecoverable::recover_signer_unchecked(tx)
            }
        }
    }
}

impl alloy_consensus::transaction::TxHashRef for SphereTxEnvelope {
    fn tx_hash(&self) -> &B256 {
        match self {
            Self::Legacy(tx) => tx.hash(),
            Self::Eip2930(tx) => tx.hash(),
            Self::Eip1559(tx) => tx.hash(),
            Self::Eip7702(tx) => tx.hash(),
            Self::Eip4844(tx) => tx.hash(),
        }
    }
}

impl fmt::Display for SphereTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy => write!(f, "Legacy"),
            Self::Eip2930 => write!(f, "EIP-2930"),
            Self::Eip1559 => write!(f, "EIP-1559"),
            Self::Eip7702 => write!(f, "EIP-7702"),
            Self::Eip4844 => write!(f, "EIP-4844"),
        }
    }
}

impl alloy_consensus::InMemorySize for SphereTxEnvelope {
    fn size(&self) -> usize {
        let (size, inline) = match self {
            Self::Legacy(tx) => (tx.size(), size_of_val(tx)),
            Self::Eip2930(tx) => (tx.size(), size_of_val(tx)),
            Self::Eip1559(tx) => (tx.size(), size_of_val(tx)),
            Self::Eip7702(tx) => (tx.size(), size_of_val(tx)),
            Self::Eip4844(tx) => (tx.size(), size_of_val(tx)),
        };
        size_of::<Self>() + size.saturating_sub(inline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_primitives::{Bytes, TxKind};
    #[test]
    fn test_system_tx_validation_and_recovery() {
        let chain_id = 1u64;

        // Valid system tx: all fields zero, correct chain_id, system signature
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let system_tx =
            SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE));

        assert!(system_tx.is_system_tx(), "Should detect system signature");
        assert!(
            system_tx.is_valid_system_tx(chain_id),
            "Should be valid system tx"
        );

        // recover_signer returns ZERO for system tx
        let signer = system_tx.recover_signer().unwrap();
        assert_eq!(
            signer,
            Address::ZERO,
            "System tx signer should be Address::ZERO"
        );

        use alloy_eips::eip2718::{Decodable2718, Encodable2718};
        let encoded = system_tx.encoded_2718();
        let recovered = SphereTxEnvelope::decode_2718(&mut encoded.as_slice()).unwrap();
        assert_eq!(recovered, system_tx);
        assert_eq!(recovered.recover_signer_unchecked().unwrap(), Address::ZERO);

        #[cfg(feature = "reth")]
        {
            use reth_codecs::Compact;
            let mut compact = Vec::new();
            let len = system_tx.to_compact(&mut compact);
            let (decoded, rest) = SphereTxEnvelope::from_compact(&compact, len);
            assert!(rest.is_empty());
            assert_eq!(decoded, system_tx);
            assert_eq!(decoded.recover_signer().unwrap(), Address::ZERO);
        }

        // Invalid: wrong chain_id
        assert!(
            !system_tx.is_valid_system_tx(2),
            "Wrong chain_id should fail"
        );

        // Invalid: non-zero gas_limit
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            gas_limit: 1, // non-zero
            ..Default::default()
        };
        let envelope =
            SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero gas_limit should fail"
        );

        // Invalid: non-zero value
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            value: U256::ONE,
            ..Default::default()
        };
        let envelope =
            SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero value should fail"
        );

        // Invalid: non-zero nonce
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 1,
            ..Default::default()
        };
        let envelope =
            SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, SPHERE_SYSTEM_TX_SIGNATURE));
        assert!(
            !envelope.is_valid_system_tx(chain_id),
            "Non-zero nonce should fail"
        );

        // Non-system tx with regular signature should recover normally
        let tx = TxLegacy::default();
        let regular_tx =
            SphereTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        assert!(
            !regular_tx.is_system_tx(),
            "Regular tx should not be system tx"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SphereTransactionKind {
    AdvanceArc,
    AdvanceArcHeaders,
    Regular,
    FinalizeWithdrawalBatch,
    UnexpectedSystem,
}

impl SphereTransactionKind {
    pub fn classify(tx: &SphereTxEnvelope) -> Self {
        if !tx.is_system_tx() {
            return Self::Regular;
        }

        if tx.to() == Some(SPHERE_INBOX_ADDRESS)
            && tx
                .input()
                .starts_with(&ISphereInbox::advanceArcCall::SELECTOR)
        {
            return Self::AdvanceArc;
        }
        if tx.to() == Some(SPHERE_INBOX_ADDRESS)
            && tx
                .input()
                .starts_with(&ISphereInbox::advanceArcHeadersCall::SELECTOR)
        {
            return Self::AdvanceArcHeaders;
        }
        if tx.to() == Some(SPHERE_OUTBOX_ADDRESS)
            && tx
                .input()
                .starts_with(&ISphereOutbox::finalizeWithdrawalBatchCall::SELECTOR)
        {
            return Self::FinalizeWithdrawalBatch;
        }
        Self::UnexpectedSystem
    }
}

#[cfg(feature = "rpc")]
mod rpc;
