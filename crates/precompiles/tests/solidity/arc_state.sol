// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Storage-only schema for the native ArcState precompile.
contract ArcStateStorage {
    bytes32 public arcBlockHash;
    uint64 public arcBlockNumber;
}
