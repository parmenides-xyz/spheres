// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    ISphereFactory,
    IVerifier,
    SphereInfo,
    TokenEnablementTransition
} from "../interfaces/ISphere.sol";

/// @title Verifier
/// @notice Verifier for quorum-certified, proofless settlement.
contract Verifier is IVerifier {

    ISphereFactory public immutable sphereFactory = ISphereFactory(msg.sender);

    /// @inheritdoc IVerifier
    function verify(
        uint32 sphereId,
        uint64,
        uint64,
        bytes32,
        uint64,
        uint256,
        BlockTransition calldata,
        DepositQueueTransition calldata,
        TokenEnablementTransition calldata,
        bytes32,
        bytes calldata verifierConfig,
        bytes calldata proof
    )
        external
        view
        override
        returns (bool)
    {
        SphereInfo memory sphere = sphereFactory.spheres(sphereId);
        if (sphere.portal == address(0) || sphere.portal != msg.sender) return false;
        return verifierConfig.length == 1 && verifierConfig[0] == 0x02 && proof.length == 0;
    }

}
