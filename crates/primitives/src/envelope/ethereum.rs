use super::SphereTxEnvelope;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, TxEip4844WithSidecar, error::ValueError};
use alloy_eips::eip7594::BlobTransactionSidecarVariant;

type EthereumSigned = EthereumTxEnvelope<TxEip4844>;
type EthereumPooled = EthereumTxEnvelope<TxEip4844WithSidecar<BlobTransactionSidecarVariant>>;

impl From<EthereumSigned> for SphereTxEnvelope {
    fn from(value: EthereumSigned) -> Self {
        match value {
            EthereumTxEnvelope::Legacy(tx) => Self::Legacy(tx),
            EthereumTxEnvelope::Eip2930(tx) => Self::Eip2930(tx),
            EthereumTxEnvelope::Eip1559(tx) => Self::Eip1559(tx),
            EthereumTxEnvelope::Eip4844(tx) => Self::Eip4844(tx),
            EthereumTxEnvelope::Eip7702(tx) => Self::Eip7702(tx),
        }
    }
}

impl From<SphereTxEnvelope> for EthereumSigned {
    fn from(value: SphereTxEnvelope) -> Self {
        match value {
            SphereTxEnvelope::Legacy(tx) => Self::Legacy(tx),
            SphereTxEnvelope::Eip2930(tx) => Self::Eip2930(tx),
            SphereTxEnvelope::Eip1559(tx) => Self::Eip1559(tx),
            SphereTxEnvelope::Eip4844(tx) => Self::Eip4844(tx),
            SphereTxEnvelope::Eip7702(tx) => Self::Eip7702(tx),
        }
    }
}

impl From<SphereTxEnvelope> for alloy_consensus::TxEnvelope {
    fn from(value: SphereTxEnvelope) -> Self {
        EthereumSigned::from(value).into()
    }
}

impl From<EthereumPooled> for SphereTxEnvelope {
    fn from(value: EthereumPooled) -> Self {
        EthereumSigned::from(value).into()
    }
}

impl TryFrom<SphereTxEnvelope> for EthereumPooled {
    type Error = ValueError<SphereTxEnvelope>;

    fn try_from(value: SphereTxEnvelope) -> Result<Self, Self::Error> {
        if value.is_system_tx() {
            return Err(ValueError::new_static(
                value,
                "system transactions cannot enter the pool",
            ));
        }
        EthereumSigned::from(value)
            .try_into_pooled()
            .map_err(|error| error.map(Into::into))
    }
}
