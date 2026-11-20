// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    DepositPayload,
    IWithdrawalReceiver,
    ISpherePortal,
    Role
} from "../../src/runtime/interfaces/ISphere.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";

enum GatewayFlow {
    Deposit,
    Redeem
}

struct GatewayCallbackData {
    GatewayFlow flow;
    address outputToken;
    uint256 keyIndex;
    DepositPayload encrypted;
    uint128 minVaultAssets;
    uint128 minVaultShares;
    uint128 minOutputAmount;
    bytes32 actionId;
    address arcRefundRecipient;
}

/// @notice Callback-only stand-in until the production SphereGateway is implemented.
/// @dev It owns its callback payload and models only the two synchronous
///      closed-loop returns. Token conversion/vault behavior is intentionally not modeled.
contract MockSphereGateway is IWithdrawalReceiver {

    error ApprovalFailed();
    error InsufficientOutputAmount(uint128 outputAmount, uint128 minOutputAmount);
    error InvalidOutputToken();
    error UnauthorizedMessenger();
    error UnregisteredGateway();

    bool public returnToSphere = true;

    function setReturnToSphere(bool enabled) external {
        returnToSphere = enabled;
    }

    function onWithdrawalReceived(
        uint32,
        address sourcePortal,
        bytes32,
        address token,
        uint128 amount,
        bytes calldata callbackData
    )
        external
        returns (bytes4)
    {
        ISpherePortal portal = ISpherePortal(sourcePortal);
        if (msg.sender != portal.messenger()) revert UnauthorizedMessenger();
        if (!portal.hasRole(address(this), Role.CallbackGateway)) {
            revert UnregisteredGateway();
        }

        GatewayCallbackData memory callback = abi.decode(callbackData, (GatewayCallbackData));
        if (callback.outputToken != token) revert InvalidOutputToken();
        if (!portal.hasRole(callback.arcRefundRecipient, Role.Account)) {
            revert ISpherePortal.AccountNotAllowed(callback.arcRefundRecipient);
        }
        if (amount < callback.minOutputAmount) {
            revert InsufficientOutputAmount(amount, callback.minOutputAmount);
        }

        if (!returnToSphere) return IWithdrawalReceiver.onWithdrawalReceived.selector;

        // The mock returns the received token. The production gateway owns conversion semantics.
        if (!IERC20(token).approve(sourcePortal, amount)) revert ApprovalFailed();
        ISpherePortal(sourcePortal)
            .deposit(
                token, amount, callback.keyIndex, callback.encrypted, callback.arcRefundRecipient
            );
        if (!IERC20(token).approve(sourcePortal, 0)) revert ApprovalFailed();

        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}
