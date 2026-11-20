// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    IVerifier,
    TokenEnablementTransition
} from "../../src/runtime/interfaces/ISphere.sol";

/// @title MockVerifier
/// @notice Mock verifier for testing that always accepts proofs (configurable)
contract MockVerifier is IVerifier {

    bool public shouldAccept = true;

    function setShouldAccept(bool _shouldAccept) external {
        shouldAccept = _shouldAccept;
    }

    function verify(
        uint32, // sphereId
        uint64, // arcBlockNumber
        uint64, // anchorBlockNumber
        bytes32, // anchorBlockHash
        uint64, // expectedWithdrawalBatchIndex
        uint256, // nextSphereHeight
        BlockTransition calldata,
        DepositQueueTransition calldata,
        TokenEnablementTransition calldata,
        bytes32, // withdrawalQueueHash
        bytes calldata, // verifierConfig
        bytes calldata // proof
    )
        external
        view
        returns (bool)
    {
        return shouldAccept;
    }

}
