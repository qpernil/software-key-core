//! Shared cryptographic building blocks for authenticated secure channels.
//!
//! This module owns cryptographic transforms and KDFs. Callers still own the
//! wire protocol, role-specific state machine, counters, policy, and errors.

use crate::software_symmetric::{aes_cmac, SoftwareSymmetricError, AES_BLOCK_SIZE};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureChannelCryptoError {
    InvalidDataLength,
    InvalidPadding,
    KeyDerivationFailed,
    OutputTooLong,
    Symmetric(SoftwareSymmetricError),
}

impl From<SoftwareSymmetricError> for SecureChannelCryptoError {
    fn from(error: SoftwareSymmetricError) -> Self {
        Self::Symmetric(error)
    }
}

/// ISO/IEC 7816-4 method-2 padding (`80 00 ... 00`) to an AES block.
pub fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    let length = (data.len() + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(data);
    output.push(0x80);
    output.resize(length, 0);
    output
}

pub fn unpad_iso7816(mut data: Vec<u8>) -> Result<Vec<u8>, SecureChannelCryptoError> {
    let marker = data
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(SecureChannelCryptoError::InvalidPadding)?;
    if data[marker] != 0x80 {
        return Err(SecureChannelCryptoError::InvalidPadding);
    }
    data.truncate(marker);
    Ok(data)
}

/// SCP03 counter-mode KDF using AES-CMAC.
pub fn scp03_kdf(
    key: &[u8],
    derivation_constant: u8,
    context: &[u8],
    output_bits: u16,
) -> Result<Vec<u8>, SecureChannelCryptoError> {
    if output_bits == 0 || output_bits % 8 != 0 {
        return Err(SecureChannelCryptoError::InvalidDataLength);
    }
    let output_length = usize::from(output_bits / 8);
    let iterations = output_length.div_ceil(AES_BLOCK_SIZE);
    if iterations > usize::from(u8::MAX) {
        return Err(SecureChannelCryptoError::OutputTooLong);
    }

    let mut output = Vec::with_capacity(iterations * AES_BLOCK_SIZE);
    for counter in 1..=iterations {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0; 11]);
        input.push(derivation_constant);
        input.push(0);
        input.extend_from_slice(&output_bits.to_be_bytes());
        input.push(counter as u8);
        input.extend_from_slice(context);
        output.extend_from_slice(&aes_cmac(key, &input)?);
    }
    output.truncate(output_length);
    Ok(output)
}

pub fn scp03_key(
    key: &[u8],
    derivation_constant: u8,
    context: &[u8],
) -> Result<[u8; AES_BLOCK_SIZE], SecureChannelCryptoError> {
    scp03_kdf(key, derivation_constant, context, 128)?
        .try_into()
        .map_err(|_| SecureChannelCryptoError::InvalidDataLength)
}

pub fn scp03_cryptogram(
    key: &[u8],
    derivation_constant: u8,
    context: &[u8],
) -> Result<[u8; 8], SecureChannelCryptoError> {
    scp03_kdf(key, derivation_constant, context, 64)?
        .try_into()
        .map_err(|_| SecureChannelCryptoError::InvalidDataLength)
}

/// ANSI X9.63 KDF with SHA-256.
pub fn x963_kdf_sha256(
    shared_secret: &[u8],
    shared_info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureChannelCryptoError> {
    let iterations = output_length.div_ceil(32);
    if iterations > u32::MAX as usize {
        return Err(SecureChannelCryptoError::OutputTooLong);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(iterations * 32));
    for counter in 1..=iterations {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update((counter as u32).to_be_bytes());
        hasher.update(shared_info);
        output.extend_from_slice(&hasher.finalize());
    }
    output.truncate(output_length);
    Ok(output)
}

/// Yubico's password-to-authentication-key derivation used by YubiHSM tools.
pub fn yubico_password_kdf(password: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(password, b"Yubico", 10_000, output.as_mut());
    output
}

/// Deterministically derive the P-256 Authentication Key used by YubiHSM's
/// asymmetric password enrollment convention.
pub fn yubico_password_p256_key(
    password: &[u8],
) -> Result<crate::software_signing::SoftwareSigningKey, SecureChannelCryptoError> {
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    input.extend_from_slice(password);
    input.push(0);
    for counter in 0..=u8::MAX {
        *input.last_mut().unwrap() = counter;
        let private = yubico_password_kdf(&input);
        if let Ok(key) = crate::software_signing::SoftwareSigningKey::from_serialized(
            crate::software_signing::SignatureScheme::EcdsaP256Sha256,
            private.as_slice(),
        ) {
            return Ok(key);
        }
    }
    Err(SecureChannelCryptoError::KeyDerivationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_and_scp03_kdf_match_known_layouts() {
        let clear = b"secure channel";
        assert_eq!(unpad_iso7816(pad_iso7816(clear)).unwrap(), clear);
        assert_eq!(
            scp03_kdf(
                &hex("404142434445464748494a4b4c4d4e4f"),
                0x04,
                &hex("01020304050607081112131415161718"),
                128,
            )
            .unwrap(),
            hex("d99675d4a95c58de629225730cddb758")
        );
    }

    #[test]
    fn yubico_password_derivation_matches_the_factory_password() {
        assert_eq!(
            yubico_password_kdf(b"password").as_slice(),
            hex("090b47dbed595654901dee1cc655e420592fd483f759e29909a04c4505d2ce0a")
        );
        assert_eq!(
            yubico_password_p256_key(b"password")
                .unwrap()
                .serialized()
                .unwrap()
                .as_slice(),
            yubico_password_kdf(b"password").as_slice()
        );
    }

    #[test]
    fn x963_kdf_is_stable_and_supports_partial_blocks() {
        assert_eq!(x963_kdf_sha256(b"secret", b"info", 33).unwrap().len(), 33);
        assert_eq!(
            x963_kdf_sha256(b"secret", b"info", 32).unwrap(),
            x963_kdf_sha256(b"secret", b"info", 32).unwrap()
        );
    }

    #[test]
    fn iso7816_unpadding_rejects_missing_and_malformed_markers() {
        assert_eq!(
            unpad_iso7816(Vec::new()),
            Err(SecureChannelCryptoError::InvalidPadding)
        );
        assert_eq!(
            unpad_iso7816(vec![0; AES_BLOCK_SIZE]),
            Err(SecureChannelCryptoError::InvalidPadding)
        );
        assert_eq!(
            unpad_iso7816(vec![0x41, 0x81, 0, 0]),
            Err(SecureChannelCryptoError::InvalidPadding)
        );
        assert_eq!(pad_iso7816(&[]), {
            let mut expected = vec![0; AES_BLOCK_SIZE];
            expected[0] = 0x80;
            expected
        });
    }

    #[test]
    fn scp03_kdf_rejects_invalid_lengths_and_keys() {
        let key = [0; AES_BLOCK_SIZE];
        assert_eq!(
            scp03_kdf(&key, 1, b"context", 0),
            Err(SecureChannelCryptoError::InvalidDataLength)
        );
        assert_eq!(
            scp03_kdf(&key, 1, b"context", 7),
            Err(SecureChannelCryptoError::InvalidDataLength)
        );
        assert_eq!(
            scp03_kdf(&[0; 15], 1, b"context", 128),
            Err(SecureChannelCryptoError::Symmetric(
                SoftwareSymmetricError::InvalidKeyLength
            ))
        );
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
