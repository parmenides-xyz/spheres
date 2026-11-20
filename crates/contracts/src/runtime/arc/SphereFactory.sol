// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FIAT_TOKEN_PROXY, ISphereFactory, SphereInfo } from "../interfaces/ISphere.sol";
import { SpherePortal } from "./SpherePortal.sol";
import { SphereMessenger } from "./SphereMessenger.sol";
import { Verifier } from "./Verifier.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";

/// @title SphereFactory
/// @notice Creates spheres and registers parameters
contract SphereFactory is ISphereFactory {

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Next sphere ID to be assigned
    /// @dev Starts at 1, reserving sphere ID 0 for potential future use (e.g., mainnet as sphere 0)
    uint32 public nextSphereId = 1;
    address public owner;
    address public immutable portalImplementation;
    address public immutable messenger;
    address public immutable verifier;

    mapping(uint32 => SphereInfo) internal _spheres;
    mapping(address => bool) internal _isSpherePortal;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        portalImplementation = address(new SpherePortal());
        messenger = address(new SphereMessenger(address(this)));
        verifier = address(new Verifier());
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                            SPHERE CREATION
    //////////////////////////////////////////////////////////////*/

    function createSphere(CreateSphereParams calldata params)
        external
        returns (uint32 sphereId, address portal)
    {
        if (msg.sender != owner) revert NotOwner();

        if (params.initialToken != FIAT_TOKEN_PROXY) revert InvalidToken();
        if (params.admin == address(0)) revert InvalidAdmin();

        sphereId = nextSphereId;
        nextSphereId = sphereId + 1;

        portal = Clones.clone(portalImplementation);
        SpherePortal(portal).initialize(
            sphereId,
            params.initialToken,
            params.accessMode,
            params.gatewayMode,
            params.allowedAccounts,
            params.sphereGateways,
            messenger,
            params.admin,
            params.sequencers,
            params.threshold,
            verifier,
            params.rpcUrl
        );

        // Store sphere info
        _spheres[sphereId] = SphereInfo({
            sphereId: sphereId,
            portal: portal,
            accessMode: params.accessMode,
            gatewayMode: params.gatewayMode,
            admin: params.admin,
            sequencers: params.sequencers,
            threshold: params.threshold,
            verifier: verifier,
            rpcUrl: params.rpcUrl
        });

        _isSpherePortal[portal] = true;

        emit SphereCreated(
            sphereId,
            portal,
            params.initialToken,
            params.accessMode,
            params.gatewayMode,
            params.admin,
            params.sequencers,
            params.threshold,
            verifier
        );
    }

    /// @inheritdoc ISphereFactory
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();

        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function spheres(uint32 id) external view returns (SphereInfo memory info) {
        return _spheres[id];
    }

    function isSpherePortal(address portal) external view returns (bool) {
        return _isSpherePortal[portal];
    }

}
