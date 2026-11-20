mod private;
pub use private::SphereRpc;
use alloy_primitives::{B256, Bytes, keccak256};
use jsonrpsee::core::RpcResult;
use reth_rpc_api::Web3ApiServer;

/// Operator Web3 API backed by the globally initialized Sphere version metadata.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OperatorWeb3Api;

#[jsonrpsee::core::async_trait]
impl Web3ApiServer for OperatorWeb3Api {
    async fn client_version(&self) -> RpcResult<String> {
        Ok(crate::version::client_version().to_owned())
    }

    fn sha3(&self, input: Bytes) -> RpcResult<B256> {
        Ok(keccak256(input))
    }
}
