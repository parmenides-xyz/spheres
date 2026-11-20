use super::SphereTxEnvelope;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError};
use alloy_network::TxSigner;
use alloy_primitives::Signature;
use alloy_rpc_types_eth::TransactionRequest;
use reth_rpc_traits::{SignTxRequestError, SignableTxRequest, TryIntoSimTx};

impl TryIntoSimTx<SphereTxEnvelope> for TransactionRequest {
    fn try_into_sim_tx(self) -> Result<SphereTxEnvelope, ValueError<Self>> {
        Self::build_typed_simulate_transaction(self).map(Into::into)
    }
}

impl SignableTxRequest<SphereTxEnvelope> for TransactionRequest {
    async fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> Result<SphereTxEnvelope, SignTxRequestError> {
        <Self as SignableTxRequest<EthereumTxEnvelope<TxEip4844>>>::try_build_and_sign(self, signer)
            .await
            .map(Into::into)
    }
}
