//! Sphere transaction policies shared by pool admission and block execution.

use alloy_primitives::Address;
use revm::context::{TxEnv, result::InvalidTransaction};

/// Validates transaction policies enforced by the Sphere EVM.
pub fn validate_transaction(
    tx: &TxEnv,
    contract_deployer_allowlist: &[Address],
) -> Result<(), InvalidTransaction> {
    if !tx.authorization_list.is_empty() {
        return Err(InvalidTransaction::AuthorizationListNotSupported);
    }

    if tx.kind.is_create() && !contract_deployer_allowlist.contains(&tx.caller) {
        return Err(InvalidTransaction::Str(
            "contract creation is not supported".into(),
        ));
    }

    Ok(())
}
