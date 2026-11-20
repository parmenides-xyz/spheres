//! `ArcState` — Sphere L2 predeploy (0x1c00...0000).

pub use ArcState::{
    ArcStateErrors as ArcStateError, ArcStateEvents as ArcStateEvent,
    finalizeArc_0Call as legacyFinalizeArcCall, finalizeArc_1Call as finalizeArcCall,
};

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract ArcState {
        event ArcBlockFinalized(bytes32 indexed blockHash, uint64 indexed blockNumber, bytes32 stateRoot);

        error InvalidParentHash();
        error InvalidBlockNumber();
        error InvalidTimestamp();
        error InvalidRlpData();
        error OnlySphereInbox();

        function readArcStorageSlot(address account,bytes32 slot) external view returns (bytes32);
        function readArcStorageSlots(address account,bytes32[] slots) external view returns (bytes32[] memory);

        function arcBlockHash() external view returns (bytes32);
        function arcBlockNumber() external view returns (uint64);

        /// Finalize one Arc header.
        function finalizeArc(bytes calldata header) external;

        /// Finalize consecutive Arc headers.
        function finalizeArc(bytes[] calldata headers) external;
    }
}

/// ArcState legacy entries.
mod legacy {
    crate::sol! {
        #[sol(abi)]
        contract ArcStateLegacy {
            function finalizeArc(bytes header) external;
        }
    }
}

#[doc(hidden)]
pub use legacy::ArcStateLegacy;
