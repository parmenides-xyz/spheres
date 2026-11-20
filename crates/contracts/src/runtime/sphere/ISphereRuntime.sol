// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import { ChaumPedersenProof } from "../interfaces/ISphere.sol";
address constant CHAUM_PEDERSEN_VERIFY = 0x1C00000000000000000000000000000000000100;
address constant AES_GCM_DECRYPT = 0x1C00000000000000000000000000000000000101;
address constant SPHERE_TX_CONTEXT = 0x1C00000000000000000000000000000000000005;

interface IChaumPedersenVerify {

    /// @notice Verify a Chaum-Pedersen proof for ECDH shared secret derivation
    /// @dev Verification equations:
    ///      - R1 = s*G - c*pubSeq
    ///      - R2 = s*ephemeralPub - c*sharedSecretPoint
    ///      - c' = hash(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)
    ///      - Check: c == c'
    /// @param ephemeralPubX The X coordinate of the ephemeral public key
    /// @param ephemeralPubYParity The Y coordinate parity (0x02 or 0x03)
    /// @param sharedSecret The claimed shared secret (x-coordinate)
    /// @param sharedSecretYParity The Y coordinate parity of the shared secret point (0x02 or 0x03)
    /// @param sequencerPubX The sequencer's public key X coordinate
    /// @param sequencerPubYParity The sequencer's public key Y parity
    /// @param proof The Chaum-Pedersen proof (s, c)
    /// @return valid True if the proof verifies correctly
    function verifyProof(
        bytes32 ephemeralPubX,
        uint8 ephemeralPubYParity,
        bytes32 sharedSecret,
        uint8 sharedSecretYParity,
        bytes32 sequencerPubX,
        uint8 sequencerPubYParity,
        ChaumPedersenProof calldata proof
    )
        external
        view
        returns (bool valid);

}

interface IAesGcmDecrypt {

    /// @notice Decrypt AES-256-GCM ciphertext and verify authentication tag
    /// @dev Returns empty bytes and false if tag verification fails.
    ///      AAD (Additional Authenticated Data) is typically empty for ECIES.
    /// @param key AES-256 key (32 bytes)
    /// @param nonce GCM nonce (12 bytes)
    /// @param ciphertext The encrypted data
    /// @param aad Additional authenticated data (use empty bytes if none)
    /// @param tag GCM authentication tag (16 bytes)
    /// @return plaintext The decrypted data (empty if verification fails)
    /// @return valid True if the tag verifies and decryption succeeds
    function decrypt(
        bytes32 key,
        bytes12 nonce,
        bytes calldata ciphertext,
        bytes calldata aad,
        bytes16 tag
    )
        external
        view
        returns (bytes memory plaintext, bool valid);

}

interface ISphereTxContext {

    /// @notice Returns the hash of the currently executing sphere transaction
    function currentTxHash() external returns (bytes32);

}

interface ISphereToken {

    function mint(address _to, uint256 _amount) external returns (bool);
    function burn(uint256 _amount) external;
    function transferFrom(address from, address to, uint256 value) external returns (bool);

}
