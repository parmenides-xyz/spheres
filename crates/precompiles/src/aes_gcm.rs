//! AES-256-GCM decryption for encrypted Sphere deposits.
//!
//! Decrypts ECIES ciphertext and verifies the GCM authentication tag for the native
//! `SphereInbox` implementation.
//!
//! Uses the NCC-audited `aes-gcm` crate (v0.10.3).

use alloc::vec::Vec;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};

/// Decrypt AES-256-GCM ciphertext with tag verification.
///
/// The ciphertext, AAD, and tag are passed separately. Returns `(plaintext, true)` on success,
/// or `(empty, false)` on failure.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
) -> (Vec<u8>, bool) {
    let cipher = Aes256Gcm::new(key.into());
    let gcm_nonce = Nonce::from_slice(nonce);
    let mut plaintext = ciphertext.to_vec();

    match cipher.decrypt_in_place_detached(gcm_nonce, aad, &mut plaintext, Tag::from_slice(tag)) {
        Ok(()) => (plaintext, true),
        Err(_) => (Vec::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(valid);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_bad_tag() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let bad_tag = [0xFFu8; 16];

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &bad_tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_with_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";
        let aad = b"sphere-inbox-v1";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, aad, &tag);
        assert!(valid);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"secret data";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: b"correct",
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, b"wrong", &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_missing_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"secret data";
        let aad = b"sphere-inbox-v1";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_flipped_ciphertext_bit() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let mut ct = encrypted[..encrypted.len() - 16].to_vec();
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        ct[0] ^= 0x01;

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, &ct, &[], &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(valid);
        assert!(decrypted.is_empty());
    }
}
