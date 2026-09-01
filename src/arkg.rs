//! Protocol-neutral ARKG-P256 key derivation.
//!
//! The public side derives an unlinkable P-256 verification key and an
//! authenticated ticket from a device's two public seed points. The private
//! side authenticates that ticket and derives the matching signing scalar from
//! the device's private seed scalars. Wire formats and seed persistence belong
//! to the caller.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    FieldBytes, ProjectivePoint, PublicKey, Scalar,
    elliptic_curve::{
        Group,
        group::ff::{Field, PrimeField},
        sec1::ToSec1Point,
    },
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const ARKG_P256_POINT_LENGTH: usize = 65;
pub const ARKG_P256_TICKET_LENGTH: usize = 16 + ARKG_P256_POINT_LENGTH;
pub const ARKG_P256_MAX_CONTEXT_LENGTH: usize = 64;
pub const ARKG_P256_MIN_IKM_LENGTH: usize = 32;

const HASH_TO_SCALAR_LENGTH: usize = 48;
const DERIVE_KEY_KEM_LABEL: &[u8] = b"ARKG-Derive-Key-KEM.";
const DERIVE_KEY_BL_LABEL: &[u8] = b"ARKG-Derive-Key-BL.";
const KEM_KEY_GENERATION_LABEL: &[u8] = b"ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256";
const ECDH_AUGMENTED_DST: &[u8] = b"ARKG-ECDH.ARKG-P256";
const KEM_MAC_LABEL: &[u8] = b"ARKG-KEM-HMAC-mac.";
const KEM_SHARED_LABEL: &[u8] = b"ARKG-KEM-HMAC-shared.";
const BLINDING_PRF_LABEL: &[u8] = b"ARKG-BL-EC.ARKG-P256";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArkgP256Error {
    ContextTooLong,
    InputKeyingMaterialTooShort,
    InvalidPrivateScalar,
    InvalidPublicPoint,
    InvalidTicketPoint,
    TicketAuthenticationFailed,
    DerivedZeroScalar,
    InvalidDomain,
    InvalidKdfLength,
    IdentityPoint,
}

impl core::fmt::Display for ArkgP256Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::ContextTooLong => "ARKG-P256 context is longer than 64 bytes",
            Self::InputKeyingMaterialTooShort => {
                "ARKG-P256 input keying material is shorter than 32 bytes"
            }
            Self::InvalidPrivateScalar => "invalid ARKG-P256 private scalar",
            Self::InvalidPublicPoint => "invalid ARKG-P256 public point",
            Self::InvalidTicketPoint => "invalid ARKG-P256 ticket point",
            Self::TicketAuthenticationFailed => "ARKG-P256 ticket authentication failed",
            Self::DerivedZeroScalar => "ARKG-P256 derived the zero scalar",
            Self::InvalidDomain => "invalid ARKG-P256 hash-to-scalar domain",
            Self::InvalidKdfLength => "invalid ARKG-P256 KDF output length",
            Self::IdentityPoint => "ARKG-P256 derived the identity point",
        })
    }
}

impl std::error::Error for ArkgP256Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArkgP256PublicDerivation {
    pub public_key: [u8; ARKG_P256_POINT_LENGTH],
    pub ticket: [u8; ARKG_P256_TICKET_LENGTH],
}

/// Return the SEC1-uncompressed public point for a private seed scalar.
pub fn arkg_p256_public_point(
    private_scalar: &[u8; 32],
) -> Result<[u8; ARKG_P256_POINT_LENGTH], ArkgP256Error> {
    projective_to_uncompressed(ProjectivePoint::GENERATOR * parse_scalar(private_scalar)?)
}

/// Derive an ARKG-P256 public key and authenticated ticket.
pub fn arkg_p256_derive_public(
    blinding_public_key: &[u8],
    kem_public_key: &[u8],
    input_keying_material: &[u8],
    context: &[u8],
) -> Result<ArkgP256PublicDerivation, ArkgP256Error> {
    if input_keying_material.len() < ARKG_P256_MIN_IKM_LENGTH {
        return Err(ArkgP256Error::InputKeyingMaterialTooShort);
    }
    let (context_kem, context_bl) = derivation_contexts(context)?;
    let blinding_public_key = PublicKey::from_sec1_bytes(blinding_public_key)
        .map_err(|_| ArkgP256Error::InvalidPublicPoint)?;
    let kem_public_key = PublicKey::from_sec1_bytes(kem_public_key)
        .map_err(|_| ArkgP256Error::InvalidPublicPoint)?;

    let ephemeral_scalar = hash_to_scalar(input_keying_material, KEM_KEY_GENERATION_LABEL)?;
    if bool::from(ephemeral_scalar.is_zero()) {
        return Err(ArkgP256Error::DerivedZeroScalar);
    }
    let ephemeral_public_key =
        projective_to_uncompressed(ProjectivePoint::GENERATOR * ephemeral_scalar)?;
    let shared_point =
        projective_to_uncompressed(kem_public_key.to_projective() * ephemeral_scalar)?;
    let shared_secret = Zeroizing::new(
        <[u8; 32]>::try_from(&shared_point[1..33])
            .map_err(|_| ArkgP256Error::InvalidPublicPoint)?,
    );

    let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let mac_key = hkdf_sha256(&shared_secret[..], &mac_info)?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
        .map_err(|_| ArkgP256Error::InvalidKdfLength)?;
    mac.update(&ephemeral_public_key);
    let tag = mac.finalize().into_bytes();

    let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let blinding_input = hkdf_sha256(&shared_secret[..], &shared_info)?;
    let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
    let tau = hash_to_scalar(&blinding_input[..], &blinding_dst)?;
    let public_key = projective_to_uncompressed(
        blinding_public_key.to_projective() + ProjectivePoint::GENERATOR * tau,
    )?;

    let mut ticket = [0u8; ARKG_P256_TICKET_LENGTH];
    ticket[..16].copy_from_slice(&tag[..16]);
    ticket[16..].copy_from_slice(&ephemeral_public_key);
    Ok(ArkgP256PublicDerivation { public_key, ticket })
}

/// Authenticate a ticket and derive its matching private signing scalar.
pub fn arkg_p256_derive_private(
    blinding_private_key: &[u8; 32],
    kem_private_key: &[u8; 32],
    ticket: &[u8; ARKG_P256_TICKET_LENGTH],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ArkgP256Error> {
    let (context_kem, context_bl) = derivation_contexts(context)?;
    let blinding_private_key = parse_scalar(blinding_private_key)?;
    let kem_private_key = parse_scalar(kem_private_key)?;
    let ephemeral =
        PublicKey::from_sec1_bytes(&ticket[16..]).map_err(|_| ArkgP256Error::InvalidTicketPoint)?;
    let shared = projective_to_uncompressed(ephemeral.to_projective() * kem_private_key)?;
    let shared_secret = Zeroizing::new(
        <[u8; 32]>::try_from(&shared[1..33]).map_err(|_| ArkgP256Error::InvalidTicketPoint)?,
    );

    let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let mac_key = hkdf_sha256(&shared_secret[..], &mac_info)?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
        .map_err(|_| ArkgP256Error::InvalidKdfLength)?;
    mac.update(&ticket[16..]);
    if !bool::from(ticket[..16].ct_eq(&mac.finalize().into_bytes()[..16])) {
        return Err(ArkgP256Error::TicketAuthenticationFailed);
    }

    let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let blinding_input = hkdf_sha256(&shared_secret[..], &shared_info)?;
    let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
    let private = blinding_private_key + hash_to_scalar(&blinding_input[..], &blinding_dst)?;
    if bool::from(private.is_zero()) {
        return Err(ArkgP256Error::DerivedZeroScalar);
    }
    Ok(Zeroizing::new(private.to_bytes().into()))
}

fn derivation_contexts(context: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ArkgP256Error> {
    let context_length = u8::try_from(context.len()).map_err(|_| ArkgP256Error::ContextTooLong)?;
    if context.len() > ARKG_P256_MAX_CONTEXT_LENGTH {
        return Err(ArkgP256Error::ContextTooLong);
    }
    let mut context_prime = Vec::with_capacity(1 + context.len());
    context_prime.push(context_length);
    context_prime.extend_from_slice(context);
    Ok((
        concatenate(&[DERIVE_KEY_KEM_LABEL, &context_prime]),
        concatenate(&[DERIVE_KEY_BL_LABEL, &context_prime]),
    ))
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<Scalar, ArkgP256Error> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .filter(|scalar| !bool::from(scalar.is_zero()))
        .ok_or(ArkgP256Error::InvalidPrivateScalar)
}

fn hkdf_sha256(
    input_keying_material: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ArkgP256Error> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, &mut *output)
        .map_err(|_| ArkgP256Error::InvalidKdfLength)?;
    Ok(output)
}

fn hash_to_scalar(message: &[u8], domain: &[u8]) -> Result<Scalar, ArkgP256Error> {
    if domain.len() > u8::MAX as usize {
        return Err(ArkgP256Error::InvalidDomain);
    }
    let mut domain_prime = Vec::with_capacity(domain.len() + 1);
    domain_prime.extend_from_slice(domain);
    domain_prime.push(u8::try_from(domain.len()).map_err(|_| ArkgP256Error::InvalidDomain)?);

    let mut b0_hasher = Sha256::new();
    b0_hasher.update([0u8; 64]);
    b0_hasher.update(message);
    b0_hasher.update([0, HASH_TO_SCALAR_LENGTH as u8]);
    b0_hasher.update([0]);
    b0_hasher.update(&domain_prime);
    let b0 = b0_hasher.finalize();

    let mut b1_hasher = Sha256::new();
    b1_hasher.update(b0);
    b1_hasher.update([1]);
    b1_hasher.update(&domain_prime);
    let b1 = b1_hasher.finalize();

    let mut xored = [0u8; 32];
    for (output, (left, right)) in xored.iter_mut().zip(b0.iter().zip(b1.iter())) {
        *output = left ^ right;
    }
    let mut b2_hasher = Sha256::new();
    b2_hasher.update(xored);
    b2_hasher.update([2]);
    b2_hasher.update(&domain_prime);
    let b2 = b2_hasher.finalize();

    let mut uniform = [0u8; HASH_TO_SCALAR_LENGTH];
    uniform[..32].copy_from_slice(&b1);
    uniform[32..].copy_from_slice(&b2[..16]);
    reduce_48_bytes(&uniform)
}

fn reduce_48_bytes(uniform: &[u8; HASH_TO_SCALAR_LENGTH]) -> Result<Scalar, ArkgP256Error> {
    let high = scalar_from_24_bytes(&uniform[..24])?;
    let low = scalar_from_24_bytes(&uniform[24..])?;
    let mut two_to_192_bytes = FieldBytes::default();
    two_to_192_bytes[7] = 1;
    let two_to_192 = Option::<Scalar>::from(Scalar::from_repr(two_to_192_bytes))
        .ok_or(ArkgP256Error::InvalidPrivateScalar)?;
    Ok(high * two_to_192 + low)
}

fn scalar_from_24_bytes(input: &[u8]) -> Result<Scalar, ArkgP256Error> {
    if input.len() != 24 {
        return Err(ArkgP256Error::InvalidPrivateScalar);
    }
    let mut bytes = FieldBytes::default();
    bytes[8..].copy_from_slice(input);
    Option::<Scalar>::from(Scalar::from_repr(bytes)).ok_or(ArkgP256Error::InvalidPrivateScalar)
}

fn projective_to_uncompressed(
    point: ProjectivePoint,
) -> Result<[u8; ARKG_P256_POINT_LENGTH], ArkgP256Error> {
    if bool::from(point.is_identity()) {
        return Err(ArkgP256Error::IdentityPoint);
    }
    let encoded = point.to_affine().to_sec1_point(false);
    let bytes = encoded.as_bytes();
    let mut output = [0u8; ARKG_P256_POINT_LENGTH];
    if bytes.len() != output.len() {
        return Err(ArkgP256Error::InvalidPublicPoint);
    }
    output.copy_from_slice(bytes);
    Ok(output)
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLINDING_PRIVATE: [u8; 32] = [
        0xd9, 0x59, 0x50, 0x0a, 0x78, 0xcc, 0xf8, 0x50, 0xce, 0x46, 0xc8, 0x0a, 0x8c, 0x50, 0x43,
        0xc9, 0xa2, 0xe3, 0x38, 0x44, 0x23, 0x2b, 0x38, 0x29, 0xdf, 0x37, 0xd0, 0x5b, 0x30, 0x69,
        0xf4, 0x55,
    ];
    const KEM_PRIVATE: [u8; 32] = [
        0x74, 0xe0, 0xa4, 0xcd, 0x81, 0xca, 0x2d, 0x24, 0x24, 0x6f, 0xf7, 0x5b, 0xfd, 0x6d, 0x4f,
        0xb7, 0xf9, 0xdf, 0xc9, 0x38, 0x37, 0x26, 0x27, 0xfe, 0xb2, 0xc2, 0x34, 0x8f, 0x8b, 0x14,
        0x93, 0xb5,
    ];

    #[test]
    fn official_vector_derives_both_sides() {
        let blinding_public = arkg_p256_public_point(&BLINDING_PRIVATE).unwrap();
        let kem_public = arkg_p256_public_point(&KEM_PRIVATE).unwrap();
        let ikm: Vec<u8> = (0x40..=0x5f).collect();
        let derived = arkg_p256_derive_public(
            &blinding_public,
            &kem_public,
            &ikm,
            b"ARKG-P256.test vectors",
        )
        .unwrap();
        assert_eq!(
            hex(&derived.public_key),
            "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd"
        );
        let private = arkg_p256_derive_private(
            &BLINDING_PRIVATE,
            &KEM_PRIVATE,
            &derived.ticket,
            b"ARKG-P256.test vectors",
        )
        .unwrap();
        assert_eq!(
            hex(&private[..]),
            "775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7"
        );
    }

    #[test]
    fn altered_ticket_is_rejected() {
        let blinding_public = arkg_p256_public_point(&BLINDING_PRIVATE).unwrap();
        let kem_public = arkg_p256_public_point(&KEM_PRIVATE).unwrap();
        let mut derived =
            arkg_p256_derive_public(&blinding_public, &kem_public, &[0x42; 32], b"context")
                .unwrap();
        derived.ticket[0] ^= 1;
        assert_eq!(
            arkg_p256_derive_private(&BLINDING_PRIVATE, &KEM_PRIVATE, &derived.ticket, b"context"),
            Err(ArkgP256Error::TicketAuthenticationFailed)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
