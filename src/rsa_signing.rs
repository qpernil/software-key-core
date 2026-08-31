//! Protocol-neutral RSA signature primitives.
//!
//! Callers choose the exact input form and encoding. This module owns the RSA
//! operations, PKCS #1 v1.5 signature padding and DigestInfo values, and
//! RSASSA-PSS encoding with independent message and MGF1 hash algorithms.

use rsa::{traits::PublicKeyParts, BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

pub use crate::digest::HashAlgorithm as RsaHashAlgorithm;

impl RsaHashAlgorithm {
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Self::Sha224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00, 0x04, 0x1c,
            ],
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            Self::Sha3_224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x07, 0x05, 0x00, 0x04, 0x1c,
            ],
            Self::Sha3_256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x08, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha3_384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x09, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha3_512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x0a, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsaPssParameters {
    pub hash: RsaHashAlgorithm,
    pub mgf_hash: RsaHashAlgorithm,
    pub salt_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaConstructionError {
    InputTooLong,
    InputOutOfRange,
    InvalidDigestLength,
    InvalidKey,
    InvalidSignature,
    RandomnessUnavailable,
    OperationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AsymmetricConstructionError<E> {
    Encoding(RsaConstructionError),
    Operation(E),
    InvalidOperationOutput,
}

fn left_pad(value: Vec<u8>, length: usize) -> Result<Vec<u8>, RsaConstructionError> {
    if value.len() > length {
        return Err(RsaConstructionError::OperationFailed);
    }
    let mut output = vec![0; length];
    output[length - value.len()..].copy_from_slice(&value);
    Ok(output)
}

fn private_operation(key: &RsaPrivateKey, encoded: &[u8]) -> Result<Vec<u8>, RsaConstructionError> {
    if encoded.len() > key.size() {
        return Err(RsaConstructionError::InputTooLong);
    }
    let value = BigUint::from_bytes_be(encoded);
    if &value >= key.n() {
        return Err(RsaConstructionError::InputOutOfRange);
    }
    let value = rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut rsa::rand_core::OsRng), &value)
        .map_err(|_| RsaConstructionError::OperationFailed)?;
    left_pad(value.to_bytes_be(), key.size())
}

fn public_operation(key: &RsaPublicKey, signature: &[u8]) -> Result<Vec<u8>, RsaConstructionError> {
    if signature.len() != key.size() {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let value = BigUint::from_bytes_be(signature);
    if &value >= key.n() {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let value = rsa::hazmat::rsa_encrypt(key, &value)
        .map_err(|_| RsaConstructionError::InvalidSignature)?;
    left_pad(value.to_bytes_be(), key.size())
}

pub fn rsa_sign_raw(key: &RsaPrivateKey, input: &[u8]) -> Result<Vec<u8>, RsaConstructionError> {
    private_operation(key, input)
}

pub fn rsa_verify_raw(
    key: &RsaPublicKey,
    input: &[u8],
    signature: &[u8],
) -> Result<(), RsaConstructionError> {
    if input.len() > key.size() {
        return Err(RsaConstructionError::InputTooLong);
    }
    let mut expected = vec![0; key.size() - input.len()];
    expected.extend_from_slice(input);
    if public_operation(key, signature)? == expected {
        Ok(())
    } else {
        Err(RsaConstructionError::InvalidSignature)
    }
}

pub fn pkcs1v15_encoded_payload(
    modulus_size: usize,
    payload: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    if payload.len() > modulus_size.saturating_sub(11) {
        return Err(RsaConstructionError::InputTooLong);
    }
    let mut encoded = vec![0, 1];
    encoded.resize(modulus_size - payload.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub fn rsa_sign_pkcs1v15_payload(
    key: &RsaPrivateKey,
    payload: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    private_operation(key, &pkcs1v15_encoded_payload(key.size(), payload)?)
}

pub fn rsa_verify_pkcs1v15_payload(
    key: &RsaPublicKey,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), RsaConstructionError> {
    let expected = pkcs1v15_encoded_payload(key.size(), payload)?;
    if public_operation(key, signature)? == expected {
        Ok(())
    } else {
        Err(RsaConstructionError::InvalidSignature)
    }
}

pub fn digest_info(hash: RsaHashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, RsaConstructionError> {
    if digest.len() != hash.output_length() {
        return Err(RsaConstructionError::InvalidDigestLength);
    }
    let mut result = hash.digest_info_prefix().to_vec();
    result.extend_from_slice(digest);
    Ok(result)
}

pub fn rsa_sign_pkcs1v15_digest(
    key: &RsaPrivateKey,
    hash: RsaHashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    rsa_sign_pkcs1v15_payload(key, &digest_info(hash, digest)?)
}

pub fn rsa_verify_pkcs1v15_digest(
    key: &RsaPublicKey,
    hash: RsaHashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaConstructionError> {
    rsa_verify_pkcs1v15_payload(key, &digest_info(hash, digest)?, signature)
}

fn mgf1(
    seed: &[u8],
    length: usize,
    hash: RsaHashAlgorithm,
) -> Result<Vec<u8>, RsaConstructionError> {
    crate::digest::mgf1(hash, seed, length).map_err(|_| RsaConstructionError::InputTooLong)
}

/// Validate and remove an RSAES-PKCS1-v1_5 type-2 encoding produced by a raw
/// RSA private operation.
pub fn rsa_pkcs1v15_unpad(encoded: &[u8]) -> Result<Vec<u8>, RsaConstructionError> {
    if encoded.len() < 11 {
        return Err(RsaConstructionError::OperationFailed);
    }
    let mut valid = encoded[0].ct_eq(&0) & encoded[1].ct_eq(&2);
    let mut found = Choice::from(0);
    let mut separator = 0u64;
    for (index, value) in encoded[2..].iter().enumerate() {
        let is_separator = value.ct_eq(&0);
        let use_index = !found & is_separator;
        separator = u64::conditional_select(&separator, &((index + 2) as u64), use_index);
        found |= is_separator;
    }
    valid &= found & separator.ct_gt(&9);
    if !bool::from(valid) {
        return Err(RsaConstructionError::OperationFailed);
    }
    Ok(encoded[separator as usize + 1..].to_vec())
}

pub fn rsa_pkcs1v15_pad(
    plaintext: &[u8],
    modulus_size: usize,
) -> Result<Vec<u8>, RsaConstructionError> {
    if plaintext.len() > modulus_size.saturating_sub(11) {
        return Err(RsaConstructionError::InputTooLong);
    }
    let padding_length = modulus_size - plaintext.len() - 3;
    let mut padding = vec![0; padding_length];
    for byte in &mut padding {
        while *byte == 0 {
            getrandom::fill(core::slice::from_mut(byte))
                .map_err(|_| RsaConstructionError::RandomnessUnavailable)?;
        }
    }
    let mut encoded = Vec::with_capacity(modulus_size);
    encoded.extend_from_slice(&[0, 2]);
    encoded.extend_from_slice(&padding);
    encoded.push(0);
    encoded.extend_from_slice(plaintext);
    Ok(encoded)
}

pub fn pkcs1v15_sign_with<E>(
    modulus_size: usize,
    payload: &[u8],
    mut private_operation: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AsymmetricConstructionError<E>> {
    let encoded = pkcs1v15_encoded_payload(modulus_size, payload)
        .map_err(AsymmetricConstructionError::Encoding)?;
    let output = private_operation(&encoded).map_err(AsymmetricConstructionError::Operation)?;
    if output.len() != modulus_size {
        return Err(AsymmetricConstructionError::InvalidOperationOutput);
    }
    Ok(output)
}

pub fn pss_sign_with<E>(
    modulus_bits: usize,
    parameters: RsaPssParameters,
    digest: &[u8],
    mut private_operation: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AsymmetricConstructionError<E>> {
    let encoded = pss_encoded_digest(modulus_bits, parameters, digest)
        .map_err(AsymmetricConstructionError::Encoding)?;
    let output = private_operation(&encoded).map_err(AsymmetricConstructionError::Operation)?;
    if output.len() != modulus_bits.div_ceil(8) {
        return Err(AsymmetricConstructionError::InvalidOperationOutput);
    }
    Ok(output)
}

pub fn oaep_encrypt_with<E>(
    modulus_size: usize,
    plaintext: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
    mut public_operation: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AsymmetricConstructionError<E>> {
    let encoded = rsa_oaep_pad_digest(plaintext, modulus_size, label_digest, mgf_hash)
        .map_err(AsymmetricConstructionError::Encoding)?;
    let output = public_operation(&encoded).map_err(AsymmetricConstructionError::Operation)?;
    if output.len() != modulus_size {
        return Err(AsymmetricConstructionError::InvalidOperationOutput);
    }
    Ok(output)
}

pub fn oaep_decrypt_with<E>(
    modulus_size: usize,
    ciphertext: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
    mut private_operation: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AsymmetricConstructionError<E>> {
    let encoded = private_operation(ciphertext).map_err(AsymmetricConstructionError::Operation)?;
    if encoded.len() != modulus_size {
        return Err(AsymmetricConstructionError::InvalidOperationOutput);
    }
    rsa_oaep_unpad_digest(&encoded, label_digest, mgf_hash)
        .map_err(AsymmetricConstructionError::Encoding)
}

pub fn pkcs1v15_decrypt_with<E>(
    modulus_size: usize,
    ciphertext: &[u8],
    mut private_operation: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AsymmetricConstructionError<E>> {
    let encoded = private_operation(ciphertext).map_err(AsymmetricConstructionError::Operation)?;
    if encoded.len() != modulus_size {
        return Err(AsymmetricConstructionError::InvalidOperationOutput);
    }
    rsa_pkcs1v15_unpad(&encoded).map_err(AsymmetricConstructionError::Encoding)
}

pub fn rsa_oaep_unpad_digest(
    encoded: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>, RsaConstructionError> {
    let hash_length = label_digest.len();
    if encoded.len() < 2 * hash_length + 2 || hash_length == 0 {
        return Err(RsaConstructionError::OperationFailed);
    }
    let (masked_seed, masked_db) = encoded[1..].split_at(hash_length);
    let seed_mask = mgf1(masked_db, hash_length, mgf_hash)?;
    let seed = masked_seed
        .iter()
        .zip(seed_mask)
        .map(|(value, mask)| value ^ mask)
        .collect::<Vec<_>>();
    let db_mask = mgf1(&seed, masked_db.len(), mgf_hash)?;
    let db = masked_db
        .iter()
        .zip(db_mask)
        .map(|(value, mask)| value ^ mask)
        .collect::<Vec<_>>();
    let mut valid = encoded[0].ct_eq(&0) & db[..hash_length].ct_eq(label_digest);
    let rest = &db[hash_length..];
    let mut looking = Choice::from(1);
    let mut separator = 0_u64;
    for (index, value) in rest.iter().enumerate() {
        let is_zero = value.ct_eq(&0);
        let is_one = value.ct_eq(&1);
        let select = looking & is_one;
        separator = u64::conditional_select(&separator, &(index as u64), select);
        valid &= !(looking & !is_zero & !is_one);
        looking &= !is_one;
    }
    valid &= !looking;
    if !bool::from(valid) {
        return Err(RsaConstructionError::OperationFailed);
    }
    Ok(rest[separator as usize + 1..].to_vec())
}

pub fn rsa_oaep_pad_digest(
    input: &[u8],
    modulus_size: usize,
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>, RsaConstructionError> {
    let hash_length = label_digest.len();
    if hash_length == 0 || input.len() > modulus_size.saturating_sub(2 * hash_length + 2) {
        return Err(RsaConstructionError::InputTooLong);
    }
    let mut db = label_digest.to_vec();
    db.resize(modulus_size - hash_length - input.len() - 2, 0);
    db.push(1);
    db.extend_from_slice(input);
    let mut seed = vec![0; hash_length];
    getrandom::fill(&mut seed).map_err(|_| RsaConstructionError::RandomnessUnavailable)?;
    let db_mask = mgf1(&seed, db.len(), mgf_hash)?;
    for (value, mask) in db.iter_mut().zip(db_mask) {
        *value ^= mask;
    }
    let seed_mask = mgf1(&db, seed.len(), mgf_hash)?;
    for (value, mask) in seed.iter_mut().zip(seed_mask) {
        *value ^= mask;
    }
    let mut encoded = Vec::with_capacity(modulus_size);
    encoded.push(0);
    encoded.extend_from_slice(&seed);
    encoded.extend_from_slice(&db);
    Ok(encoded)
}

/// Decrypt an RSAES-PKCS1-v1_5 ciphertext and validate its type-2 encoding.
pub fn rsa_decrypt_pkcs1v15(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    if ciphertext.len() != key.size() {
        return Err(RsaConstructionError::InputTooLong);
    }
    key.decrypt_blinded(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, ciphertext)
        .map_err(|_| RsaConstructionError::OperationFailed)
}

pub fn rsa_encrypt_pkcs1v15(
    key: &RsaPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    public_operation(key, &rsa_pkcs1v15_pad(plaintext, key.size())?)
}

/// Decrypt RSAES-OAEP where the caller supplies the already-computed label
/// digest, as required by the YubiHSM command protocol.
pub fn rsa_decrypt_oaep_digest(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>, RsaConstructionError> {
    if ciphertext.len() != key.size() || !matches!(label_digest.len(), 20 | 32 | 48 | 64) {
        return Err(RsaConstructionError::InputTooLong);
    }
    rsa_oaep_unpad_digest(&private_operation(key, ciphertext)?, label_digest, mgf_hash)
}

pub fn rsa_encrypt_oaep_digest(
    key: &RsaPublicKey,
    plaintext: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>, RsaConstructionError> {
    if !matches!(label_digest.len(), 20 | 32 | 48 | 64) {
        return Err(RsaConstructionError::InvalidDigestLength);
    }
    public_operation(
        key,
        &rsa_oaep_pad_digest(plaintext, key.size(), label_digest, mgf_hash)?,
    )
}

pub fn pss_encoded_digest(
    modulus_bits: usize,
    parameters: RsaPssParameters,
    digest: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    if digest.len() != parameters.hash.output_length() {
        return Err(RsaConstructionError::InvalidDigestLength);
    }
    let em_bits = modulus_bits
        .checked_sub(1)
        .ok_or(RsaConstructionError::InvalidKey)?;
    let em_len = em_bits.div_ceil(8);
    let hash_length = parameters.hash.output_length();
    if em_len < hash_length + parameters.salt_length + 2 {
        return Err(RsaConstructionError::InputTooLong);
    }
    let mut salt = vec![0; parameters.salt_length];
    getrandom::fill(&mut salt).map_err(|_| RsaConstructionError::RandomnessUnavailable)?;
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    let h = parameters.hash.digest(&m_prime);
    let mut db = vec![0; em_len - parameters.salt_length - hash_length - 2];
    db.push(1);
    db.extend_from_slice(&salt);
    let mask = mgf1(&h, db.len(), parameters.mgf_hash)?;
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    db.extend_from_slice(&h);
    db.push(0xbc);
    Ok(db)
}

pub fn rsa_sign_pss_digest(
    key: &RsaPrivateKey,
    parameters: RsaPssParameters,
    digest: &[u8],
) -> Result<Vec<u8>, RsaConstructionError> {
    private_operation(
        key,
        &pss_encoded_digest(key.n().bits(), parameters, digest)?,
    )
}

pub fn rsa_verify_pss_digest(
    key: &RsaPublicKey,
    parameters: RsaPssParameters,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaConstructionError> {
    let recovered = public_operation(key, signature)?;
    verify_pss_encoded_digest(&recovered, key.n().bits(), parameters, digest)
}

pub fn verify_pss_encoded_digest(
    encoded: &[u8],
    modulus_bits: usize,
    parameters: RsaPssParameters,
    digest: &[u8],
) -> Result<(), RsaConstructionError> {
    if digest.len() != parameters.hash.output_length() {
        return Err(RsaConstructionError::InvalidDigestLength);
    }
    let em_bits = modulus_bits
        .checked_sub(1)
        .ok_or(RsaConstructionError::InvalidKey)?;
    let em_len = em_bits.div_ceil(8);
    let prefix_length = encoded
        .len()
        .checked_sub(em_len)
        .ok_or(RsaConstructionError::InvalidSignature)?;
    if encoded[..prefix_length].iter().any(|byte| *byte != 0) {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let encoded = &encoded[prefix_length..];
    let hash_length = parameters.hash.output_length();
    if encoded.len() < hash_length + parameters.salt_length + 2 || encoded.last() != Some(&0xbc) {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let h_offset = encoded.len() - hash_length - 1;
    let masked_db = &encoded[..h_offset];
    let h = &encoded[h_offset..h_offset + hash_length];
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits != 0
        && masked_db
            .first()
            .is_some_and(|value| *value & (0xff << (8 - unused_bits)) != 0)
    {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let mask = mgf1(h, masked_db.len(), parameters.mgf_hash)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> unused_bits;
    let separator = db
        .len()
        .checked_sub(parameters.salt_length + 1)
        .ok_or(RsaConstructionError::InvalidSignature)?;
    if db.get(separator) != Some(&1) || db[..separator].iter().any(|value| *value != 0) {
        return Err(RsaConstructionError::InvalidSignature);
    }
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&db[separator + 1..]);
    if parameters.hash.digest(&m_prime) == h {
        Ok(())
    } else {
        Err(RsaConstructionError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2_048).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    #[test]
    fn raw_and_pkcs1_payload_signatures_round_trip() {
        let (private, public) = key_pair();
        for (sign, verify) in [
            (
                rsa_sign_raw as fn(&RsaPrivateKey, &[u8]) -> _,
                rsa_verify_raw as fn(&RsaPublicKey, &[u8], &[u8]) -> _,
            ),
            (rsa_sign_pkcs1v15_payload, rsa_verify_pkcs1v15_payload),
        ] {
            let signature = sign(&private, b"caller-controlled payload").unwrap();
            verify(&public, b"caller-controlled payload", &signature).unwrap();
            assert_eq!(
                verify(&public, b"changed", &signature),
                Err(RsaConstructionError::InvalidSignature)
            );
        }
    }

    #[test]
    fn every_digest_info_hash_round_trips() {
        let (private, public) = key_pair();
        for hash in [
            RsaHashAlgorithm::Sha1,
            RsaHashAlgorithm::Sha224,
            RsaHashAlgorithm::Sha256,
            RsaHashAlgorithm::Sha384,
            RsaHashAlgorithm::Sha512,
            RsaHashAlgorithm::Sha3_224,
            RsaHashAlgorithm::Sha3_256,
            RsaHashAlgorithm::Sha3_384,
            RsaHashAlgorithm::Sha3_512,
        ] {
            let digest = hash.digest(b"message");
            let signature = rsa_sign_pkcs1v15_digest(&private, hash, &digest).unwrap();
            rsa_verify_pkcs1v15_digest(&public, hash, &digest, &signature).unwrap();
        }
    }

    #[test]
    fn sha256_digest_info_is_canonical_der() {
        let digest = [0xa5; 32];
        let mut expected = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        expected.extend_from_slice(&digest);
        assert_eq!(digest_info(RsaHashAlgorithm::Sha256, &digest), Ok(expected));
    }

    #[test]
    fn pss_supports_independent_hash_mgf_and_salt() {
        let (private, public) = key_pair();
        let parameters = RsaPssParameters {
            hash: RsaHashAlgorithm::Sha3_384,
            mgf_hash: RsaHashAlgorithm::Sha256,
            salt_length: 37,
        };
        let digest = parameters.hash.digest(b"message");
        let signature = rsa_sign_pss_digest(&private, parameters, &digest).unwrap();
        rsa_verify_pss_digest(&public, parameters, &digest, &signature).unwrap();
        let wrong = RsaPssParameters {
            salt_length: 36,
            ..parameters
        };
        assert_eq!(
            rsa_verify_pss_digest(&public, wrong, &digest, &signature),
            Err(RsaConstructionError::InvalidSignature)
        );
    }

    #[test]
    fn callback_constructions_compose_with_raw_rsa_capabilities() {
        let (private, public) = key_pair();
        let signature = pkcs1v15_sign_with(private.size(), b"payload", |encoded| {
            private_operation(&private, encoded)
        })
        .unwrap();
        rsa_verify_pkcs1v15_payload(&public, b"payload", &signature).unwrap();

        let label_digest = RsaHashAlgorithm::Sha256.digest(b"label");
        let ciphertext = oaep_encrypt_with(
            public.size(),
            b"secret",
            &label_digest,
            RsaHashAlgorithm::Sha256,
            |encoded| public_operation(&public, encoded),
        )
        .unwrap();
        assert_eq!(
            oaep_decrypt_with(
                private.size(),
                &ciphertext,
                &label_digest,
                RsaHashAlgorithm::Sha256,
                |value| private_operation(&private, value),
            )
            .unwrap(),
            b"secret"
        );
    }

    #[test]
    fn pkcs1_and_oaep_padding_reject_malformed_encodings() {
        let pkcs1 = rsa_pkcs1v15_pad(b"secret", 64).unwrap();
        assert_eq!(rsa_pkcs1v15_unpad(&pkcs1).unwrap(), b"secret");
        for malformed in [
            vec![0; 10],
            vec![0, 1, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6],
            vec![0, 2, 1, 2, 3, 4, 5, 6, 7, 0, 9],
            vec![0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        ] {
            assert_eq!(
                rsa_pkcs1v15_unpad(&malformed),
                Err(RsaConstructionError::OperationFailed)
            );
        }

        let label = RsaHashAlgorithm::Sha256.digest(b"label");
        let encoded =
            rsa_oaep_pad_digest(b"secret", 128, &label, RsaHashAlgorithm::Sha256).unwrap();
        assert_eq!(
            rsa_oaep_unpad_digest(&encoded, &label, RsaHashAlgorithm::Sha256).unwrap(),
            b"secret"
        );
        let wrong_label = RsaHashAlgorithm::Sha256.digest(b"other label");
        assert_eq!(
            rsa_oaep_unpad_digest(&encoded, &wrong_label, RsaHashAlgorithm::Sha256),
            Err(RsaConstructionError::OperationFailed)
        );
        assert_eq!(
            rsa_oaep_unpad_digest(&[0; 16], &label, RsaHashAlgorithm::Sha256),
            Err(RsaConstructionError::OperationFailed)
        );
    }

    #[test]
    fn pss_encoding_rejects_wrong_digests_parameters_and_tampering() {
        let parameters = RsaPssParameters {
            hash: RsaHashAlgorithm::Sha256,
            mgf_hash: RsaHashAlgorithm::Sha384,
            salt_length: 24,
        };
        let digest = parameters.hash.digest(b"message");
        let mut encoded = pss_encoded_digest(2_048, parameters, &digest).unwrap();
        verify_pss_encoded_digest(&encoded, 2_048, parameters, &digest).unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_pss_encoded_digest(&encoded, 2_048, parameters, &digest),
            Err(RsaConstructionError::InvalidSignature)
        );
        assert_eq!(
            pss_encoded_digest(2_048, parameters, &[0; 31]),
            Err(RsaConstructionError::InvalidDigestLength)
        );
        assert_eq!(
            pss_encoded_digest(1, parameters, &digest),
            Err(RsaConstructionError::InputTooLong)
        );
        assert_eq!(
            digest_info(RsaHashAlgorithm::Sha512, &[0; 63]),
            Err(RsaConstructionError::InvalidDigestLength)
        );
    }

    #[test]
    fn callback_constructions_preserve_errors_and_validate_output_lengths() {
        assert_eq!(
            pkcs1v15_sign_with(128, b"payload", |_| Err::<Vec<u8>, _>("unavailable")),
            Err(AsymmetricConstructionError::Operation("unavailable"))
        );
        assert_eq!(
            pkcs1v15_sign_with(128, b"payload", |_| { Ok::<_, &'static str>(vec![0; 127]) }),
            Err(AsymmetricConstructionError::InvalidOperationOutput)
        );

        let label = RsaHashAlgorithm::Sha256.digest(b"label");
        assert_eq!(
            oaep_decrypt_with(128, b"ciphertext", &label, RsaHashAlgorithm::Sha256, |_| {
                Ok::<_, &'static str>(vec![0; 127])
            }),
            Err(AsymmetricConstructionError::InvalidOperationOutput)
        );
        assert_eq!(
            pss_sign_with(
                1_024,
                RsaPssParameters {
                    hash: RsaHashAlgorithm::Sha256,
                    mgf_hash: RsaHashAlgorithm::Sha256,
                    salt_length: 32,
                },
                &[0; 31],
                |_| Ok::<_, &'static str>(vec![0; 128]),
            ),
            Err(AsymmetricConstructionError::Encoding(
                RsaConstructionError::InvalidDigestLength
            ))
        );
    }

    #[test]
    fn raw_rsa_rejects_out_of_range_inputs_and_wrong_signature_sizes() {
        let (private, public) = key_pair();
        assert_eq!(
            rsa_sign_raw(&private, &vec![0xff; private.size() + 1]),
            Err(RsaConstructionError::InputTooLong)
        );
        assert_eq!(
            rsa_verify_raw(&public, b"input", &[0; 1]),
            Err(RsaConstructionError::InvalidSignature)
        );
        assert_eq!(
            rsa_verify_raw(
                &public,
                &vec![0; public.size() + 1],
                &vec![0; public.size()],
            ),
            Err(RsaConstructionError::InputTooLong)
        );
    }
}
