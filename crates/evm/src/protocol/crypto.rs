use alloy_evm::precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap};
use alloy_primitives::{Address, B256, Bytes, address};
use alloy_sol_types::{SolCall, SolError};
use revm::{
    interpreter::Gas,
    precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult},
};
use sphere_contracts::spheres::{ISphereInbox, SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS};
use sphere_precompiles::{aes_gcm, chaum_pedersen, tx_context};
alloy_sol_types::sol! {
struct ChaumPedersenProof {
    bytes32 s; // Response: s = r + c * privSeq (mod n)
    bytes32 c; // Challenge: c = hash(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)
}
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
}
const CHAUM_PEDERSEN_VERIFY: Address = address!("0x1C00000000000000000000000000000000000100");
const AES_GCM_DECRYPT: Address = address!("0x1C00000000000000000000000000000000000101");
const SPHERE_TX_CONTEXT: Address = address!("0x1C00000000000000000000000000000000000005");

pub(super) fn configure_runtime(precompiles: &mut PrecompilesMap) {
    precompiles.extend_precompiles([
        (
            CHAUM_PEDERSEN_VERIFY,
            DynPrecompile::new_stateful(PrecompileId::Custom("ChaumPedersenVerify".into()), run),
        ),
        (
            AES_GCM_DECRYPT,
            DynPrecompile::new_stateful(PrecompileId::Custom("AesGcmDecrypt".into()), run),
        ),
        (
            SPHERE_TX_CONTEXT,
            DynPrecompile::new_stateful(PrecompileId::Custom("SphereTxContext".into()), run),
        ),
    ]);
}
fn run(input: PrecompileInput<'_>) -> PrecompileResult {
    let mut gas = Gas::new(input.gas);
    let permitted_caller = if input.target_address == SPHERE_TX_CONTEXT {
        SPHERE_OUTBOX_ADDRESS
    } else {
        SPHERE_INBOX_ADDRESS
    };
    if !input.is_direct_call() || input.caller != permitted_caller || !input.value.is_zero() {
        return Ok(PrecompileOutput::revert(
            gas.used(),
            ISphereInbox::Unauthorized {}.abi_encode().into(),
            input.reservoir,
        ));
    }
    let oog = || PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir);
    if !gas.record_regular_cost((input.data.len() as u64).div_ceil(32).saturating_mul(30)) {
        return Ok(oog());
    }
    let empty_revert = || PrecompileOutput::revert(gas.used(), Bytes::new(), input.reservoir);
    let encoded = if input.target_address == CHAUM_PEDERSEN_VERIFY {
        let Ok(call) = IChaumPedersenVerify::verifyProofCall::abi_decode_validate(input.data)
        else {
            return Ok(empty_revert());
        };
        if !gas.record_regular_cost(6000) {
            return Ok(oog());
        }
        let proof = sphere_contracts::ChaumPedersenProof {
            s: call.proof.s,
            c: call.proof.c,
        };
        let valid = chaum_pedersen::verify(
            &call.ephemeralPubX.0,
            call.ephemeralPubYParity,
            &call.sharedSecret.0,
            call.sharedSecretYParity,
            &call.sequencerPubX.0,
            call.sequencerPubYParity,
            &proof,
        );
        IChaumPedersenVerify::verifyProofCall::abi_encode_returns(&valid)
    } else if input.target_address == AES_GCM_DECRYPT {
        let Ok(call) = IAesGcmDecrypt::decryptCall::abi_decode_validate(input.data) else {
            return Ok(empty_revert());
        };
        let len = call.ciphertext.len().saturating_add(call.aad.len()) as u64;
        if !gas.record_regular_cost(1000u64.saturating_add(3u64.saturating_mul(len))) {
            return Ok(oog());
        }
        let (plaintext, valid) = aes_gcm::decrypt(
            &call.key.0,
            &call.nonce.0,
            &call.ciphertext,
            &call.aad,
            &call.tag.0,
        );
        IAesGcmDecrypt::decryptCall::abi_encode_returns(&IAesGcmDecrypt::decryptReturn {
            plaintext: plaintext.into(),
            valid,
        })
    } else {
        if ISphereTxContext::currentTxHashCall::abi_decode_validate(input.data).is_err() {
            return Ok(empty_revert());
        }
        let hash = tx_context::current_transaction()
            .map(|(hash, _)| hash)
            .unwrap_or(B256::ZERO);
        ISphereTxContext::currentTxHashCall::abi_encode_returns(&hash)
    };
    Ok(PrecompileOutput::new(
        gas.used(),
        encoded.into(),
        input.reservoir,
    ))
}
