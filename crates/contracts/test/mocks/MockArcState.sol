// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    PORTAL_MAX_ARC_GAS_RATE_SLOT,
    PORTAL_ROLE_SLOT,
    PORTAL_TOKEN_CONFIGS_SLOT,
    Role
} from "../../src/runtime/interfaces/ISphere.sol";

/// @title MockArcState
/// @notice Mock ArcState for testing SphereInbox
/// @dev Allows setting storage slot values and simulates finalizeArc
contract MockArcState {

    address public immutable sequencer;

    // Core fields (matching real ArcState)
    bytes32 public arcBlockHash;
    uint64 public arcBlockNumber;

    /// @notice Mock storage values for readArcStorageSlot
    mapping(address => mapping(bytes32 => bytes32)) public mockStorageValues;

    error OnlySequencer();

    constructor(
        address _sequencer,
        bytes32 _genesisArcBlockHash,
        uint64 _genesisArcBlockNumber
    ) {
        sequencer = _sequencer;
        arcBlockHash = _genesisArcBlockHash;
        arcBlockNumber = _genesisArcBlockNumber;
    }

    /// @notice Set a mock storage value for readArcStorageSlot
    function setMockStorageValue(address account, bytes32 slot, bytes32 value) external {
        mockStorageValues[account][slot] = value;
    }

    function setMockMaxArcGasRate(address portal, uint128 rate) external {
        mockStorageValues[portal][PORTAL_MAX_ARC_GAS_RATE_SLOT] = bytes32(uint256(rate));
    }

    /// @notice Set the mocked SpherePortal TokenConfig.enabled field.
    function setMockTokenEnabled(address portal, address token, bool enabled) external {
        bytes32 configSlot = keccak256(abi.encode(token, PORTAL_TOKEN_CONFIGS_SLOT));
        uint256 raw = uint256(mockStorageValues[portal][configSlot]);
        raw = (raw & ~uint256(0xff)) | (enabled ? 1 : 0);
        mockStorageValues[portal][configSlot] = bytes32(raw);
    }

    function setMockAccountAllowed(address portal, address account, bool allowed) external {
        bytes32 slot = keccak256(abi.encode(account, PORTAL_ROLE_SLOT));
        mockStorageValues[portal][slot] = allowed ? bytes32(uint256(Role.Account)) : bytes32(0);
    }

    function setMockSphereGateway(address portal, address gateway, bool enabled) external {
        bytes32 gatewaySlot = keccak256(abi.encode(gateway, PORTAL_ROLE_SLOT));
        mockStorageValues[portal][gatewaySlot] =
            enabled ? bytes32(uint256(Role.CallbackGateway)) : bytes32(0);
    }

    /// @notice Mock finalizeArc - just advances block number
    /// @dev No sequencer check here - SphereInbox already validates the caller
    function finalizeArc(bytes[] calldata headers) external {
        arcBlockNumber += uint64(headers.length);
        arcBlockHash = keccak256(abi.encode(arcBlockHash, arcBlockNumber));
    }

    /// @notice Mock readArcStorageSlot - returns preset values
    function readArcStorageSlot(address account, bytes32 slot) external view returns (bytes32) {
        return mockStorageValues[account][slot];
    }

}
