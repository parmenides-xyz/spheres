// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IWithdrawalReceiver,
    ISphereFactory,
    ISphereMessenger,
    ISpherePortal,
    Role,
    SphereInfo
} from "../interfaces/ISphere.sol";
import { INativeFiatToken } from "./SpherePortal.sol";

/// @title SphereMessenger
/// @notice Shared withdrawal callback sender for all spheres created by one SphereFactory.
contract SphereMessenger is ISphereMessenger {

    ISphereFactory public immutable sphereFactory;

    uint256 internal _relayReentrancyStatus;

    error UnauthorizedPortal();
    error TransferFailed();
    error CallbackRejected();
    error InvalidCallbackTarget();
    error ReentrantRelay();

    constructor(address _sphereFactory) {
        sphereFactory = ISphereFactory(_sphereFactory);
    }

    modifier nonReentrantRelay() {
        if (_relayReentrancyStatus != 0) revert ReentrantRelay();
        _relayReentrancyStatus = 1;
        _;
        _relayReentrancyStatus = 0;
    }

    function relayMessage(
        uint32 sphereId,
        address token,
        bytes32 senderTag,
        address target,
        uint128 amount,
        uint64 gasLimit,
        bytes calldata data
    )
        external
        nonReentrantRelay
    {
        SphereInfo memory sphere = sphereFactory.spheres(sphereId);
        if (sphere.portal != msg.sender) revert UnauthorizedPortal();

        if (
            !ISpherePortal(msg.sender).isGatewayOpen()
                && !ISpherePortal(msg.sender).hasRole(target, Role.CallbackGateway)
        ) {
            revert InvalidCallbackTarget();
        }

        if (!INativeFiatToken(token).transfer(target, amount)) {
            revert TransferFailed();
        }

        // The target is untrusted, so the empty `catch` drops its revert data. Copying it would
        // cost quadratic memory gas here and again in the portal, well past `gasLimit`.
        try IWithdrawalReceiver(target).onWithdrawalReceived{ gas: gasLimit }(
            sphereId, msg.sender, senderTag, token, amount, data
        ) returns (
            bytes4 selector
        ) {
            if (selector != IWithdrawalReceiver.onWithdrawalReceived.selector) {
                revert CallbackRejected();
            }
        } catch {
            revert CallbackRejected();
        }
    }

}
