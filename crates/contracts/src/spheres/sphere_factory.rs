//! `SphereFactory` ABI.

pub use SphereFactory::SphereInfo;

/// Maximum number of sequencers in a Sphere's active sequencer set.
pub const MAX_SEQUENCERS: usize = 8;

crate::sol! {
    #[sol(abi)]
    #[derive(Debug)]
    contract SphereFactory {
        struct SphereInfo {
            uint32 sphereId;
            address portal;
            bool accessMode;
            bool gatewayMode;
            address admin;
            address[] sequencers;
            uint8 threshold;
            address verifier;
            string rpcUrl;
        }
        struct CreateSphereParams {
            address initialToken;
            bool accessMode;
            bool gatewayMode;
            address[] allowedAccounts;
            address[] sphereGateways;
            address admin;
            address[] sequencers;
            uint8 threshold;
            string rpcUrl;
        }
        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        event SphereCreated(
            uint32 indexed sphereId,
            address indexed portal,
            address initialToken,
            bool accessMode,
            bool gatewayMode,
            address admin,
            address[] sequencers,
            uint8 threshold,
            address verifier
        );
        error InvalidToken();
        error NotOwner();
        error InvalidAdmin();
        error InvalidSequencerSet();
        error InvalidClosedLoopConfig();
        error DuplicateAllowedAccount();
        error DuplicateSphereGateway();
        function owner() external view returns (address);
        function transferOwnership(address newOwner) external;
        function createSphere(CreateSphereParams calldata params) external returns (uint32 sphereId, address portal);
        function spheres(uint32 sphereId) external view returns (SphereInfo memory);
        function nextSphereId() external view returns (uint32);
        function isSpherePortal(address portal) external view returns (bool);
    }
}
