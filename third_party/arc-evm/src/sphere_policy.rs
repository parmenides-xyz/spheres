use alloy_primitives::Address;
use alloy_sol_types::SolInterface;
use sphere_contracts::{SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS};

alloy_sol_types::sol!(
    #[sol(ignore_unlinked)]
    NativeFiatToken,
    "../../assets/artifacts/stablecoin-contracts/NativeFiatTokenV2_2.json"
);

pub(super) enum CallCheck { Continue, Transfer, Revert }

pub(super) fn check_usdc_call(data: &[u8], caller: Address) -> CallCheck {
    use NativeFiatToken::NativeFiatTokenCalls as Call;
    let Ok(call) = Call::abi_decode(data) else { return CallCheck::Revert; };
    let allowed = match call {
        Call::balanceOf(call) => caller == call.account,
        Call::allowance(call) => [call.owner, call.spender].contains(&caller),
        Call::nonces(call) => caller == call.owner,
        Call::authorizationState(call) => caller == call.authorizer,
        Call::minterAllowance(call) => caller == call.minter,
        Call::mint(_) => caller == SPHERE_INBOX_ADDRESS,
        Call::burn(_) => caller == SPHERE_OUTBOX_ADDRESS,
        Call::transferFrom(call) if caller == SPHERE_OUTBOX_ADDRESS && call.to == SPHERE_OUTBOX_ADDRESS => true,
        Call::transfer(_) | Call::transferFrom(_) | Call::transferWithAuthorization_0(_) | Call::transferWithAuthorization_1(_)
        | Call::receiveWithAuthorization_0(_) | Call::receiveWithAuthorization_1(_) => return CallCheck::Transfer,
        Call::CANCEL_AUTHORIZATION_TYPEHASH(_)
        | Call::DECIMALS_SCALING_FACTOR(_)
        | Call::DOMAIN_SEPARATOR(_)
        | Call::NATIVE_COIN_AUTHORITY(_)
        | Call::NATIVE_COIN_CONTROL(_)
        | Call::PERMIT_TYPEHASH(_)
        | Call::RECEIVE_WITH_AUTHORIZATION_TYPEHASH(_)
        | Call::TRANSFER_WITH_AUTHORIZATION_TYPEHASH(_)
        | Call::blacklister(_)
        | Call::currency(_)
        | Call::decimals(_)
        | Call::masterMinter(_)
        | Call::name(_)
        | Call::owner(_)
        | Call::paused(_)
        | Call::pauser(_)
        | Call::rescuer(_)
        | Call::symbol(_)
        | Call::totalSupply(_)
        | Call::isBlacklisted(_)
        | Call::isMinter(_)
        | Call::approve(_)
        | Call::increaseAllowance(_)
        | Call::decreaseAllowance(_)
        | Call::permit_0(_)
        | Call::permit_1(_)
        | Call::cancelAuthorization_0(_)
        | Call::cancelAuthorization_1(_) => true,
        _ => false,
    };
    if allowed { CallCheck::Continue } else { CallCheck::Revert }
}
