//! SMB2 message signing (HMAC-SHA256).
//!
//! SMB2 uses HMAC-SHA256 over the session signing key to sign messages.
//! The signature occupies bytes 48..64 of the SMB2 header.
//!
//! MS-SMB2 Section 3.1.4.1 (signing)

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The byte range in the SMB2 header that holds the 16-byte signature.
pub const SIGNATURE_OFFSET: usize = 48;
pub const SIGNATURE_LEN: usize = 16;

/// Compute and write the HMAC-SHA256 signature into the message buffer.
///
/// `key` is the session signing key (typically 16 bytes derived from auth).
/// `message` is the full SMB2 message (header + body) as a mutable byte slice.
/// The signature field (bytes 48..64) is zeroed before computing, then overwritten.
pub fn sign_message(key: &[u8], message: &mut [u8]) {
    if key.is_empty() || message.len() < 64 {
        return;
    }

    // Zero the signature field before computing
    message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message);
    let result = mac.finalize().into_bytes();

    // Copy the first 16 bytes of the HMAC into the signature field
    message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
        .copy_from_slice(&result[..SIGNATURE_LEN]);
}

/// Verify the HMAC-SHA256 signature of a received message.
///
/// Returns `true` if the signature is valid or if `key` is empty (unsigned).
pub fn verify_signature(key: &[u8], message: &[u8]) -> bool {
    if key.is_empty() {
        return true; // signing not configured
    }
    if message.len() < 64 {
        return false;
    }

    // Save the original signature
    let mut original_sig = [0u8; SIGNATURE_LEN];
    original_sig.copy_from_slice(&message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]);

    // Make a mutable copy with the signature field zeroed
    let mut msg_copy = message.to_vec();
    msg_copy[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&msg_copy);
    let result = mac.finalize().into_bytes();

    // Compare first 16 bytes
    result[..SIGNATURE_LEN] == original_sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let key = b"session-signing-key!";
        let mut message = vec![0u8; 128]; // fake SMB2 message
        // Put some recognizable data
        message[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        message[70..75].copy_from_slice(b"hello");

        sign_message(key, &mut message);

        // Signature should be non-zero now
        assert_ne!(&message[48..64], &[0u8; 16]);

        // Verification should pass
        assert!(verify_signature(key, &message));

        // Tamper with a byte → verification should fail
        message[70] = b'X';
        assert!(!verify_signature(key, &message));
    }

    #[test]
    fn test_empty_key_skips() {
        let mut message = vec![0u8; 64];
        sign_message(b"", &mut message);
        assert_eq!(&message[48..64], &[0u8; 16]); // unchanged

        assert!(verify_signature(b"", &message)); // empty key always passes
    }
}
