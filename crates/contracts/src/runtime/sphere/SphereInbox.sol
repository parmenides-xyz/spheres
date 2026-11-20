// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    DecryptionData,
    Deposit,
    DepositType,
    EnabledToken,
    FIAT_TOKEN_PROXY,
    IArcState,
    ISphereInbox,
    ISphereOutbox,
    PORTAL_CURRENT_DEPOSIT_QUEUE_HASH_SLOT,
    PORTAL_ENABLED_TOKENS_SLOT,
    PORTAL_ENCRYPTION_KEYS_SLOT,
    PORTAL_ROLE_SLOT,
    PORTAL_TOKEN_ENABLEMENT_HASH_SLOT,
    QueuedDeposit,
    Role,
    SPHERE_OUTBOX,
    WithdrawalBounceBackDeposit
} from "../interfaces/ISphere.sol";
import {
    ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE,
    EncryptedDepositLib
} from "../libraries/EncryptedDeposit.sol";
import {
    AES_GCM_DECRYPT,
    CHAUM_PEDERSEN_VERIFY,
    IAesGcmDecrypt,
    IChaumPedersenVerify,
    ISphereToken
} from "./ISphereRuntime.sol";

/// @title SphereInbox
/// @notice Sphere-side system contract for advancing Arc state and processing deposits
/// @dev Called by the block executor as a system transaction. Combines Arc header advancement
///      with deposit queue processing in a single atomic operation.
contract SphereInbox is ISphereInbox {

    error NoRefund();

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The Arc portal address (for reading deposit queue hash)
    address public immutable arcPortal;

    /// @notice The ArcState predeploy address (stored as concrete type for internal use)
    IArcState internal immutable _arcState;

    /// @notice Last processed deposit queue hash (validated against Arc state)
    bytes32 public processedDepositQueueHash;

    /// @notice Last processed deposit number (mirrors lastProcessedDepositNumber on L1)
    uint64 public processedDepositNumber;

    /// @notice Refunds parked after a withdrawal-bounce-back mint reverts on the sphere.
    mapping(address token => mapping(address owner => uint128 amount)) private _refunds;

    /// @notice Last portal token-enablement commitment applied by this sphere.
    bytes32 public processedTokenEnablementHash;
    uint64 public processedEnabledTokenCount;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _arcPortalAddr, address _arcStateAddr) {
        arcPortal = _arcPortalAddr;
        _arcState = IArcState(_arcStateAddr);
    }

    modifier onlyRefundOwnerOrSequencer(address owner) {
        if (msg.sender != owner && !_isSequencer(msg.sender)) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice The ArcState predeploy address
    function arcState() external view returns (IArcState) {
        return _arcState;
    }

    /// @notice Return a parked refund to its owner or an active sequencer.
    /// @dev Authorization is enforced here so internal calls cannot bypass RPC policy.
    function refunds(
        address token,
        address owner
    )
        external
        view
        onlyRefundOwnerOrSequencer(owner)
        returns (uint128)
    {
        return _refunds[token][owner];
    }

    /*//////////////////////////////////////////////////////////////
                         CRYPTOGRAPHIC HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev HMAC ipad constant (0x36 repeated 32 times)
    bytes32 private constant _IPAD =
        0x3636363636363636363636363636363636363636363636363636363636363636;
    /// @dev HMAC opad constant (0x5c repeated 32 times)
    bytes32 private constant _OPAD =
        0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;

    /// @notice HMAC-SHA256 implementation using the SHA256 precompile
    /// @dev HMAC(key, message) = SHA256((key ⊕ opad) || SHA256((key ⊕ ipad) || message))
    ///      where ipad = 0x36 repeated, opad = 0x5c repeated.
    ///      Uses word-level XOR instead of byte-by-byte loops for ~95% gas reduction.
    /// @param key The HMAC key (will be hashed if longer than 64 bytes)
    /// @param message The message to authenticate
    /// @return result The 32-byte HMAC-SHA256 output
    function _hmacSha256(
        bytes memory key,
        bytes memory message
    )
        internal
        view
        returns (bytes32 result)
    {
        // Load key into two 32-byte words (SHA256 block size = 64 bytes = 2 words)
        bytes32 keyWord0;
        bytes32 keyWord1;

        if (key.length > 64) {
            // Key longer than block size: hash it first (result goes in first word, second is zero)
            keyWord0 = sha256(key);
        } else {
            assembly {
                let keyLen := mload(key)
                keyWord0 := mload(add(key, 32))
                // Load second word only if key > 32 bytes
                switch gt(keyLen, 32)
                case 1 {
                    keyWord1 := mload(add(key, 64))
                }
                default {
                    keyWord1 := 0
                }
                // Zero out bytes beyond key length in first word
                if lt(keyLen, 32) {
                    let shift := mul(sub(32, keyLen), 8)
                    keyWord0 := and(keyWord0, not(sub(shl(shift, 1), 1)))
                }
                // Zero out bytes beyond key length in second word
                if and(gt(keyLen, 32), lt(keyLen, 64)) {
                    let shift := mul(sub(64, keyLen), 8)
                    keyWord1 := and(keyWord1, not(sub(shl(shift, 1), 1)))
                }
            }
        }

        // Inner hash: SHA256((key ⊕ ipad) || message)
        bytes32 innerHash = sha256(abi.encodePacked(keyWord0 ^ _IPAD, keyWord1 ^ _IPAD, message));

        // Outer hash: SHA256((key ⊕ opad) || innerHash)
        result = sha256(abi.encodePacked(keyWord0 ^ _OPAD, keyWord1 ^ _OPAD, innerHash));
    }

    /// @notice HKDF-SHA256 key derivation (simplified single-output version)
    /// @dev Implements HKDF-Extract and HKDF-Expand to derive a 32-byte key
    ///      from the input key material (shared secret).
    /// @param ikm Input key material (the ECDH shared secret)
    /// @param salt Salt value (use "ecies-aes-key" for ECIES)
    /// @param info Context-specific info (typically empty for ECIES)
    /// @return okm Output key material (32 bytes for AES-256)
    function _hkdfSha256(
        bytes32 ikm,
        bytes memory salt,
        bytes memory info
    )
        internal
        view
        returns (bytes32 okm)
    {
        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
        bytes32 prk = _hmacSha256(salt, abi.encodePacked(ikm));

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        // We only need 32 bytes (one block), so N=1 and we append 0x01
        bytes memory expandInput = bytes.concat(info, hex"01");
        okm = _hmacSha256(abi.encodePacked(prk), expandInput);
    }

    function _hashTokenEnablement(
        bytes32 previousHash,
        EnabledToken memory token
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(previousHash, token.token, token.name, token.symbol, token.currency)
        );
    }

    function _readEncryptionKey(uint256 keyIndex) internal view returns (bytes32 x, uint8 yParity) {
        uint256 base = uint256(keccak256(abi.encode(uint256(PORTAL_ENCRYPTION_KEYS_SLOT))));
        uint256 slotX = base + (keyIndex * 2);
        uint256 slotMeta = slotX + 1;
        bytes32 xSlot = _arcState.readArcStorageSlot(arcPortal, bytes32(slotX));
        if (xSlot == bytes32(0)) revert InvalidSharedSecretProof();
        bytes32 metaSlot = _arcState.readArcStorageSlot(arcPortal, bytes32(slotMeta));
        // yParity is packed in the lowest byte of the meta slot (see EncryptionKeyEntry layout)
        return (xSlot, uint8(uint256(metaSlot) & 0xff));
    }

    /*//////////////////////////////////////////////////////////////
                         SYSTEM TRANSACTION
    //////////////////////////////////////////////////////////////*/

    function advanceArcHeaders(bytes[] calldata headers) external {
        if (msg.sender != address(0)) revert OnlySequencer();
        _arcState.finalizeArc(headers);
    }

    /// @notice Advance Arc state and process deposits in a single system transaction
    /// @dev This is the main entry point for the sequencer's system transaction.
    ///      1. Advances the sphere's view of Arc by processing the header
    ///      2. Processes user deposits and internal withdrawal bounce-backs
    ///      3. Requires the resulting hash chain to equal Arc's currentDepositQueueHash
    ///      Protocol and proof enforce at most one call at the start of a block (or zero if skipping).
    /// @param header RLP-encoded Arc block header
    /// @param deposits All queued deposits through the current head, oldest first
    /// @param decryptions Decryption data for valid user deposits, in order
    function advanceArc(
        bytes calldata header,
        QueuedDeposit[] calldata deposits,
        DecryptionData[] calldata decryptions,
        EnabledToken[] calldata enabledTokens
    )
        external
    {
        if (msg.sender != address(0)) revert OnlySequencer();

        // Step 1: Advance Arc state (validates chain continuity internally)
        bytes[] memory headers = new bytes[](1);
        headers[0] = header;
        _arcState.finalizeArc(headers);

        // Authenticate the complete append-only token-enablement delta before activating any
        // token or processing any deposit.
        bytes32 nextTokenEnablementHash = processedTokenEnablementHash;
        for (uint256 i = 0; i < enabledTokens.length; i++) {
            nextTokenEnablementHash =
                _hashTokenEnablement(nextTokenEnablementHash, enabledTokens[i]);
        }
        bytes32 arcTokenEnablementHash =
            _arcState.readArcStorageSlot(arcPortal, PORTAL_TOKEN_ENABLEMENT_HASH_SLOT);
        if (nextTokenEnablementHash != arcTokenEnablementHash) {
            revert InvalidTokenEnablementHash();
        }

        // Activate new tokens directly in the Inbox.
        for (uint256 i = 0; i < enabledTokens.length; i++) {
            EnabledToken calldata t = enabledTokens[i];
            if (t.token != FIAT_TOKEN_PROXY) revert InvalidTokenEnablementHash();
            emit TokenEnabled(t.token, t.name, t.symbol, t.currency);
        }
        if (enabledTokens.length != 0) {
            processedTokenEnablementHash = nextTokenEnablementHash;
        }

        if (processedEnabledTokenCount == 0) {
            uint256 count =
                uint256(_arcState.readArcStorageSlot(arcPortal, PORTAL_ENABLED_TOKENS_SLOT));
            if (count > type(uint64).max) revert InvalidTokenEnablementHash();
            processedEnabledTokenCount = uint64(count);
        } else {
            processedEnabledTokenCount += uint64(enabledTokens.length);
        }

        // Step 2: Process deposits and build hash chain
        bytes32 currentHash = processedDepositQueueHash;
        uint256 decryptionIndex = 0;

        for (uint256 i = 0; i < deposits.length; i++) {
            QueuedDeposit calldata qd = deposits[i];

            if (qd.depositType == DepositType.WithdrawalBounceBack) {
                WithdrawalBounceBackDeposit memory d =
                    abi.decode(qd.depositData, (WithdrawalBounceBackDeposit));
                currentHash =
                    keccak256(abi.encode(DepositType.WithdrawalBounceBack, d, currentHash));
                if (keccak256(qd.depositData) != keccak256(abi.encode(d))) {
                    revert InvalidDepositQueueHash();
                }

                if (d.token != FIAT_TOKEN_PROXY) revert InvalidDepositQueueHash();
                _processWithdrawalBounceBack(d);
            } else {
                Deposit memory ed = abi.decode(qd.depositData, (Deposit));
                if (keccak256(qd.depositData) != keccak256(abi.encode(ed))) {
                    revert InvalidDepositQueueHash();
                }
                if (ed.token != FIAT_TOKEN_PROXY) revert InvalidDepositQueueHash();
                currentHash = keccak256(abi.encode(DepositType.Deposit, ed, currentHash));

                // The sequencer must provide decryption data for this deposit.
                if (decryptionIndex >= decryptions.length) {
                    revert MissingDecryptionData();
                }
                DecryptionData calldata dec = decryptions[decryptionIndex++];

                // Step 1: Verify Chaum-Pedersen proof of correct shared secret derivation
                // This prevents griefing attacks where users encrypt with wrong keys,
                // without exposing the sequencer's private key to the EVM.
                // The proof verifies that sharedSecret = privSeq * ephemeralPub without revealing privSeq.
                // The sequencer's public key is looked up on-chain from the deposit's keyIndex,
                // so it doesn't need to be in DecryptionData (saves calldata).
                (bytes32 seqPubX, uint8 seqPubYParity) = _readEncryptionKey(ed.keyIndex);
                bool proofValid = IChaumPedersenVerify(CHAUM_PEDERSEN_VERIFY)
                    .verifyProof(
                        ed.encrypted.ephemeralPubkeyX,
                        ed.encrypted.ephemeralPubkeyYParity,
                        dec.sharedSecret,
                        dec.sharedSecretYParity,
                        seqPubX,
                        seqPubYParity,
                        dec.cpProof
                    );

                bool valid = proofValid;
                bytes memory decryptedPlaintext;
                if (valid) {
                    // Step 2: Derive AES key from shared secret and the public deposit sender
                    // using HKDF-SHA256. Binding the sender prevents a valid encrypted payload
                    // from being replayed by another account to dust its hidden recipient.
                    // This is done in Solidity using the SHA256 precompile (0x02)
                    bytes32 aesKey = _hkdfSha256(
                        dec.sharedSecret,
                        "ecies-aes-key",
                        abi.encodePacked(
                            arcPortal, ed.keyIndex, ed.encrypted.ephemeralPubkeyX, ed.sender
                        )
                    );

                    // Step 3: Decrypt using AES-256-GCM precompile
                    // The GCM tag proves the plaintext matches the ciphertext for this shared secret
                    (decryptedPlaintext, valid) = IAesGcmDecrypt(AES_GCM_DECRYPT)
                        .decrypt(
                            aesKey,
                            ed.encrypted.nonce,
                            ed.encrypted.ciphertext,
                            "", // empty AAD
                            ed.encrypted.tag
                        );
                }

                // Step 4: Decode the decrypted (to, memo) from the plaintext.
                // Plaintext is packed as [address(20 bytes)][memo(32 bytes)][padding(12 bytes)]
                // and must be exactly ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE (64) bytes.
                if (!valid || decryptedPlaintext.length != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE) {
                    _failDeposit(currentHash, ed);
                    continue;
                }
                (address decryptedTo, bytes32 decryptedMemo) =
                    EncryptedDepositLib.decodePlaintext(decryptedPlaintext);

                try ISphereToken(ed.token).mint(decryptedTo, ed.amount) {
                    emit DepositProcessed(
                        currentHash, ed.sender, decryptedTo, ed.token, ed.amount, decryptedMemo
                    );
                } catch {
                    _failDeposit(currentHash, ed);
                }
            }
        }

        // Verify all decryption data was consumed
        if (decryptionIndex != decryptions.length) revert ExtraDecryptionData();

        // Step 3: Validate against Arc state
        // Read currentDepositQueueHash from the portal's storage using the new Arc state.
        // The system transaction is all-or-nothing: every queued deposit through the current
        // queue head must be processed in this call, or the entire call reverts. That rollback
        // also undoes the Arc checkpoint, token activation, and any deposit-side effects above.
        bytes32 arcCurrentHash =
            _arcState.readArcStorageSlot(arcPortal, PORTAL_CURRENT_DEPOSIT_QUEUE_HASH_SLOT);

        if (currentHash != arcCurrentHash) revert InvalidDepositQueueHash();

        // Step 4: Update state
        processedDepositQueueHash = currentHash;
        processedDepositNumber += uint64(deposits.length);

        emit ArcAdvanced(
            _arcState.arcBlockHash(),
            _arcState.arcBlockNumber(),
            deposits.length,
            currentHash,
            processedDepositNumber,
            processedEnabledTokenCount
        );
    }

    function _failDeposit(bytes32 currentHash, Deposit memory ed) internal {
        _enqueueDepositBounceBack(ed.token, ed.amount, ed.arcRefundRecipient);
        emit DepositFailed(currentHash, ed.sender, ed.token, ed.amount);
    }

    function _enqueueDepositBounceBack(
        address token,
        uint128 amount,
        address arcRefundRecipient
    )
        internal
    {
        ISphereOutbox(SPHERE_OUTBOX).enqueueDepositBounceBack(token, amount, arcRefundRecipient);
    }

    function _isSequencer(address account) internal view returns (bool) {
        bytes32 slot = keccak256(abi.encode(account, PORTAL_ROLE_SLOT));
        return
            uint8(uint256(_arcState.readArcStorageSlot(arcPortal, slot))) == uint8(Role.Sequencer);
    }

    function _processWithdrawalBounceBack(WithdrawalBounceBackDeposit memory d) internal {
        uint64 fallbackNonce = uint64(uint160(d.to));
        address sphereFallbackRecipient =
            ISphereOutbox(SPHERE_OUTBOX).consumeFallbackRecipient(fallbackNonce);
        try ISphereToken(d.token).mint(sphereFallbackRecipient, d.amount) {
            emit WithdrawalBounceBackProcessed(sphereFallbackRecipient, d.token, d.amount);
        } catch {
            _refunds[d.token][sphereFallbackRecipient] += d.amount;
            emit WithdrawalBounceBackPending(sphereFallbackRecipient, d.token, d.amount);
        }
    }

    function claimRefund(address token) external returns (uint128 amount) {
        amount = _refunds[token][msg.sender];
        if (amount == 0) revert NoRefund();
        _refunds[token][msg.sender] = 0;

        ISphereToken(token).mint(msg.sender, amount);
        emit RefundClaimed(msg.sender, token, amount);
    }

}
