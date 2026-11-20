//! Privacy policy enforcement helpers.
//!
//! Shared by [`SphereRpcApi`] implementations.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Address;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_consensus::TxEnvelope;
use sphere_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

use crate::{auth::AuthContext, types::JsonRpcError};

/// Enforce all redacted RPC authorization rules for simulation-style requests.
pub fn enforce_authorized(
    request: &mut TransactionRequest,
    auth: &AuthContext,
) -> Result<(), JsonRpcError> {
    enforce_from(request, auth)?;
    enforce_contract_creation(request, auth.caller)
}

/// Enforce that `from` matches the authenticated caller.
///
/// - If `from` is omitted, sets it to `auth.caller`.
/// - If present and mismatched, returns `-32004 Account mismatch`.
pub fn enforce_from(
    request: &mut TransactionRequest,
    auth: &AuthContext,
) -> Result<(), JsonRpcError> {
    match request.from {
        Some(from) if from != auth.caller => Err(JsonRpcError::account_mismatch()),
        None => {
            request.from = Some(auth.caller);
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Apply the protocol contract-deployer allowlist to create-style transaction requests.
///
pub fn enforce_contract_creation(
    request: &TransactionRequest,
    caller: Address,
) -> Result<(), JsonRpcError> {
    enforce_contract_creation_with_allowlist(request, caller, CONTRACT_DEPLOYER_ALLOWLIST)
}

fn enforce_contract_creation_with_allowlist(
    request: &TransactionRequest,
    caller: Address,
    allowlist: &[Address],
) -> Result<(), JsonRpcError> {
    if allowlist.contains(&caller) {
        return Ok(());
    }

    if request.to.unwrap_or(alloy_primitives::TxKind::Create).is_create() {
        return Err(JsonRpcError::invalid_params(
            "contract creation not supported on spheres",
        ));
    }

    Ok(())
}

/// Decode a raw transaction and verify the recovered sender matches the
/// authenticated caller. Returns `-32003 Transaction rejected` on mismatch.
pub fn verify_raw_tx_sender(data: &[u8], auth: &AuthContext) -> Result<(), JsonRpcError> {
    let tx = TxEnvelope::decode_2718_exact(data)
        .map_err(|_| JsonRpcError::invalid_params("failed to decode transaction"))?;

    let sender = tx
        .recover_signer()
        .map_err(|_| JsonRpcError::invalid_params("invalid transaction signature"))?;

    if sender != auth.caller {
        return Err(JsonRpcError::transaction_rejected());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, TxKind};
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};

    use super::{enforce_contract_creation, enforce_contract_creation_with_allowlist};

    fn call_target(byte: u8) -> TxKind {
        TxKind::Call(Address::repeat_byte(byte))
    }

    fn call_request(to: Option<TxKind>) -> TransactionRequest {
        TransactionRequest {
            to,
            input: TransactionInput::new(Bytes::default()),
            ..Default::default()
        }
    }

    #[test]
    fn contract_creation_policy_allows_standard_call_request() {
        let request = call_request(Some(call_target(0x11)));
        assert!(enforce_contract_creation(&request, Address::repeat_byte(0x01)).is_ok());
    }

    #[test]
    fn contract_creation_policy_rejects_plain_create_request() {
        let request = call_request(None);
        let err = enforce_contract_creation(&request, Address::repeat_byte(0x01)).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "contract creation not supported on spheres");
    }

    #[test]
    fn contract_creation_policy_rejects_explicit_outer_create_request() {
        let request = call_request(Some(TxKind::Create));
        let err = enforce_contract_creation(&request, Address::repeat_byte(0x01)).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "contract creation not supported on spheres");
    }

    #[test]
    fn contract_creation_policy_allows_designated_deployer() {
        let caller = Address::repeat_byte(0x11);
        let request = call_request(None);

        assert!(enforce_contract_creation_with_allowlist(&request, caller, &[]).is_err());
        assert!(enforce_contract_creation_with_allowlist(&request, caller, &[caller]).is_ok());
    }
}
