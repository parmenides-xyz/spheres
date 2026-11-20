use super::SphereTxEnvelope;
use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy, TxType};
use alloy_primitives::Signature;
use alloy_rlp::BufMut;
use reth_codecs::{
    Compact,
    alloy::transaction::{CompactEnvelope, Envelope, FromTxCompact, ToTxCompact},
};

impl ToTxCompact for SphereTxEnvelope {
    fn to_tx_compact(&self, buf: &mut (impl BufMut + AsMut<[u8]>)) {
        match self {
            Self::Legacy(tx) => tx.tx().to_compact(buf),
            Self::Eip2930(tx) => tx.tx().to_compact(buf),
            Self::Eip1559(tx) => tx.tx().to_compact(buf),
            Self::Eip4844(tx) => tx.tx().to_compact(buf),
            Self::Eip7702(tx) => tx.tx().to_compact(buf),
        };
    }
}

impl FromTxCompact for SphereTxEnvelope {
    type TxType = TxType;

    fn from_tx_compact(buf: &[u8], tx_type: TxType, signature: Signature) -> (Self, &[u8]) {
        match tx_type {
            TxType::Legacy => {
                let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                let tx = Signed::new_unhashed(tx, signature);
                (Self::Legacy(tx), buf)
            }
            TxType::Eip2930 => {
                let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                let tx = Signed::new_unhashed(tx, signature);
                (Self::Eip2930(tx), buf)
            }
            TxType::Eip1559 => {
                let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                let tx = Signed::new_unhashed(tx, signature);
                (Self::Eip1559(tx), buf)
            }
            TxType::Eip4844 => {
                let (tx, buf) = TxEip4844::from_compact(buf, buf.len());
                let tx = Signed::new_unhashed(tx, signature);
                (Self::Eip4844(tx), buf)
            }
            TxType::Eip7702 => {
                let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                let tx = Signed::new_unhashed(tx, signature);
                (Self::Eip7702(tx), buf)
            }
        }
    }
}

impl Envelope for SphereTxEnvelope {
    fn signature(&self) -> &Signature {
        match self {
            Self::Legacy(tx) => tx.signature(),
            Self::Eip2930(tx) => tx.signature(),
            Self::Eip1559(tx) => tx.signature(),
            Self::Eip4844(tx) => tx.signature(),
            Self::Eip7702(tx) => tx.signature(),
        }
    }

    fn tx_type(&self) -> Self::TxType {
        match self {
            Self::Legacy(_) => TxType::Legacy,
            Self::Eip2930(_) => TxType::Eip2930,
            Self::Eip1559(_) => TxType::Eip1559,
            Self::Eip4844(_) => TxType::Eip4844,
            Self::Eip7702(_) => TxType::Eip7702,
        }
    }
}

impl Compact for SphereTxEnvelope {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        <Self as CompactEnvelope>::to_compact(self, buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        <Self as CompactEnvelope>::from_compact(buf, len)
    }
}

use alloy_primitives::bytes;
reth_codecs::impl_compression_for_compact!(SphereTxEnvelope);
