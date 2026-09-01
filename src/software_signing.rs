//! Protocol-neutral software signing keys.
//!
//! This module owns key generation, compact private-key serialization, public
//! projection, message and prehash signing, verification, and algorithm-specific
//! controls such as RSA-PSS salt length. Callers retain responsibility for
//! protocol identifiers, public-key containers, signature formatting, policy,
//! and error mapping.

use crate::{
    brainpool512::{BrainpoolP512r1, SecretKey as BrainpoolP512SecretKey},
    post_quantum::{validate_ml_dsa_public_key, verify_ml_dsa, MlDsaParameterSet, MlDsaPrivateKey},
    rsa_signing::{
        rsa_decrypt_oaep_digest, rsa_decrypt_pkcs1v15, rsa_encrypt_oaep_digest,
        rsa_encrypt_pkcs1v15, rsa_sign_pkcs1v15_digest, rsa_sign_pkcs1v15_payload,
        rsa_sign_pss_digest, rsa_sign_raw, rsa_verify_pkcs1v15_digest, rsa_verify_pss_digest,
        rsa_verify_raw, RsaConstructionError, RsaHashAlgorithm, RsaPssParameters,
    },
};
use bp256::r1::SecretKey as BrainpoolP256SecretKey;
use bp384::r1::SecretKey as BrainpoolP384SecretKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use elliptic_curve::pkcs8::{
    DecodePrivateKey as DecodeEcPrivateKey, EncodePrivateKey as EncodeEcPrivateKey,
};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::SecretKey as K256SecretKey;
use p224::SecretKey as P224SecretKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::SecretKey as P384SecretKey;
use p521::ecdsa::SigningKey as P521SigningKey;
use p521::SecretKey as P521SecretKey;
use rsa::pkcs8::{
    DecodePrivateKey as DecodeRsaPrivateKey, EncodePrivateKey as EncodeRsaPrivateKey,
};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::{Signer, Verifier};
use std::fmt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A signing operation, independent of how the private key was created or stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureScheme {
    EcdsaP224Sha224,
    EcdsaP256Sha256,
    Ed25519,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    EcdsaSecp256k1Sha256,
    EcdsaBrainpoolP256Sha256,
    EcdsaBrainpoolP384Sha384,
    EcdsaBrainpoolP512Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    MlDsa(MlDsaParameterSet),
}

impl SignatureScheme {
    const fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaPssSha256
                | Self::RsaPssSha384
                | Self::RsaPssSha512
                | Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha384
                | Self::RsaPkcs1Sha512
        )
    }

    /// Return the curve used by an ECDSA algorithm, independently of where
    /// the corresponding private key is implemented.
    pub const fn ec_curve(self) -> Option<EcCurve> {
        match self {
            Self::EcdsaP224Sha224 => Some(EcCurve::P224),
            Self::EcdsaP256Sha256 => Some(EcCurve::P256),
            Self::EcdsaP384Sha384 => Some(EcCurve::P384),
            Self::EcdsaP521Sha512 => Some(EcCurve::P521),
            Self::EcdsaSecp256k1Sha256 => Some(EcCurve::Secp256k1),
            Self::EcdsaBrainpoolP256Sha256 => Some(EcCurve::BrainpoolP256),
            Self::EcdsaBrainpoolP384Sha384 => Some(EcCurve::BrainpoolP384),
            Self::EcdsaBrainpoolP512Sha512 => Some(EcCurve::BrainpoolP512),
            Self::Ed25519
            | Self::RsaPssSha256
            | Self::RsaPssSha384
            | Self::RsaPssSha512
            | Self::RsaPkcs1Sha256
            | Self::RsaPkcs1Sha384
            | Self::RsaPkcs1Sha512
            | Self::MlDsa(_) => None,
        }
    }
}

/// Compatibility name for callers which have not yet adopted the explicit
/// key-kind/signature-scheme terminology.
#[deprecated(note = "use SignatureScheme")]
pub type SoftwareSigningAlgorithm = SignatureScheme;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSigningError {
    AlgorithmMismatch,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    RandomnessUnavailable,
    SigningFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcCurve {
    P224,
    P256,
    P384,
    P521,
    Secp256k1,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
}

impl EcCurve {
    /// Return the signature scheme supported for this curve by the shared
    /// software implementation.
    pub const fn signature_scheme(self) -> SignatureScheme {
        match self {
            Self::P224 => SignatureScheme::EcdsaP224Sha224,
            Self::P256 => SignatureScheme::EcdsaP256Sha256,
            Self::P384 => SignatureScheme::EcdsaP384Sha384,
            Self::P521 => SignatureScheme::EcdsaP521Sha512,
            Self::Secp256k1 => SignatureScheme::EcdsaSecp256k1Sha256,
            Self::BrainpoolP256 => SignatureScheme::EcdsaBrainpoolP256Sha256,
            Self::BrainpoolP384 => SignatureScheme::EcdsaBrainpoolP384Sha384,
            Self::BrainpoolP512 => SignatureScheme::EcdsaBrainpoolP512Sha512,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoftwarePublicKey {
    Ec {
        curve: EcCurve,
        uncompressed: Vec<u8>,
    },
    Ed25519([u8; 32]),
    MlDsa {
        parameter_set: MlDsaParameterSet,
        public_key: Vec<u8>,
    },
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
}

macro_rules! verify_ecdsa {
    ($ec:ident, $public:expr, $message:expr, $signature:expr) => {{
        let key = $ec::ecdsa::VerifyingKey::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = $ec::ecdsa::Signature::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify($message, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

macro_rules! verify_ecdsa_prehash {
    ($ec:ident, $public:expr, $prehash:expr, $signature:expr) => {{
        let key = $ec::ecdsa::VerifyingKey::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = $ec::ecdsa::Signature::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify_prehash($prehash, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

macro_rules! verify_generic_ecdsa {
    ($curve:ty, $public:expr, $message:expr, $signature:expr) => {{
        let key = ecdsa::VerifyingKey::<$curve>::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = ecdsa::Signature::<$curve>::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify($message, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

macro_rules! verify_generic_ecdsa_prehash {
    ($curve:ty, $public:expr, $prehash:expr, $signature:expr) => {{
        let key = ecdsa::VerifyingKey::<$curve>::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = ecdsa::Signature::<$curve>::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify_prehash($prehash, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

impl SoftwarePublicKey {
    /// Validate that the encoded public key is structurally valid and belongs
    /// to the declared algorithm family.
    pub fn validate(&self) -> Result<(), SoftwareSigningError> {
        match self {
            Self::Ec {
                curve,
                uncompressed,
            } => {
                macro_rules! validate_ec {
                    ($curve:ty) => {
                        ecdsa::VerifyingKey::<$curve>::from_sec1_bytes(uncompressed)
                            .map(|_| ())
                            .map_err(|_| SoftwareSigningError::InvalidPublicKey)
                    };
                }
                match curve {
                    EcCurve::P224 => validate_ec!(p224::NistP224),
                    EcCurve::P256 => validate_ec!(p256::NistP256),
                    EcCurve::P384 => validate_ec!(p384::NistP384),
                    EcCurve::P521 => validate_ec!(p521::NistP521),
                    EcCurve::Secp256k1 => validate_ec!(k256::Secp256k1),
                    EcCurve::BrainpoolP256 => validate_ec!(bp256::BrainpoolP256r1),
                    EcCurve::BrainpoolP384 => validate_ec!(bp384::BrainpoolP384r1),
                    EcCurve::BrainpoolP512 => validate_ec!(BrainpoolP512r1),
                }
            }
            Self::Ed25519(public) => ed25519_dalek::VerifyingKey::from_bytes(public)
                .map(|_| ())
                .map_err(|_| SoftwareSigningError::InvalidPublicKey),
            Self::MlDsa {
                parameter_set,
                public_key,
            } => validate_ml_dsa_public_key(*parameter_set, public_key)
                .map_err(|_| SoftwareSigningError::InvalidPublicKey),
            Self::Rsa { modulus, exponent } => rsa_public_key(modulus, exponent).map(|_| ()),
        }
    }

    pub fn encrypt_rsa_pkcs1v15(&self, plaintext: &[u8]) -> Result<Vec<u8>, SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_encrypt_pkcs1v15(&rsa_public_key(modulus, exponent)?, plaintext)
            .map_err(map_rsa_signing_error)
    }

    pub fn encrypt_rsa_oaep_digest(
        &self,
        plaintext: &[u8],
        label_digest: &[u8],
        mgf_hash: RsaHashAlgorithm,
    ) -> Result<Vec<u8>, SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_encrypt_oaep_digest(
            &rsa_public_key(modulus, exponent)?,
            plaintext,
            label_digest,
            mgf_hash,
        )
        .map_err(map_rsa_signing_error)
    }

    /// Verify a raw RSA private-key operation against the caller-supplied
    /// modulus-width encoded input.
    pub fn verify_rsa_raw(
        &self,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let key = rsa_public_key(modulus, exponent)?;
        rsa_verify_raw(&key, input, signature).map_err(map_rsa_verification_error)
    }

    /// Verify a signature over an unhashed message.
    ///
    /// ECDSA signatures use fixed-width `r || s`; Ed25519 and ML-DSA use their
    /// standard raw encodings. Protocol layers remain responsible for
    /// converting formats such as WebAuthn's DER-encoded ECDSA signatures.
    pub fn verify_message(
        &self,
        algorithm: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        match (algorithm, self) {
            (
                SignatureScheme::EcdsaP224Sha224,
                Self::Ec {
                    curve: EcCurve::P224,
                    uncompressed,
                },
            ) => verify_ecdsa!(p224, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaP256Sha256,
                Self::Ec {
                    curve: EcCurve::P256,
                    uncompressed,
                },
            ) => verify_ecdsa!(p256, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaP384Sha384,
                Self::Ec {
                    curve: EcCurve::P384,
                    uncompressed,
                },
            ) => verify_ecdsa!(p384, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaP521Sha512,
                Self::Ec {
                    curve: EcCurve::P521,
                    uncompressed,
                },
            ) => verify_ecdsa!(p521, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaSecp256k1Sha256,
                Self::Ec {
                    curve: EcCurve::Secp256k1,
                    uncompressed,
                },
            ) => verify_ecdsa!(k256, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaBrainpoolP256Sha256,
                Self::Ec {
                    curve: EcCurve::BrainpoolP256,
                    uncompressed,
                },
            ) => verify_generic_ecdsa!(bp256::BrainpoolP256r1, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaBrainpoolP384Sha384,
                Self::Ec {
                    curve: EcCurve::BrainpoolP384,
                    uncompressed,
                },
            ) => verify_generic_ecdsa!(bp384::BrainpoolP384r1, uncompressed, message, signature),
            (
                SignatureScheme::EcdsaBrainpoolP512Sha512,
                Self::Ec {
                    curve: EcCurve::BrainpoolP512,
                    uncompressed,
                },
            ) => {
                use sha2::Digest as _;
                crate::brainpool512::verify_prehash(
                    uncompressed,
                    &sha2::Sha512::digest(message),
                    signature,
                )
                .map_err(|_| SoftwareSigningError::InvalidSignature)
            }
            (SignatureScheme::Ed25519, Self::Ed25519(public)) => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(public)
                    .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
                let signature = ed25519_dalek::Signature::try_from(signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)
            }
            (
                SignatureScheme::MlDsa(expected),
                Self::MlDsa {
                    parameter_set,
                    public_key,
                },
            ) if expected == *parameter_set => {
                verify_ml_dsa(*parameter_set, public_key, message, &[], signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)
            }
            (
                algorithm @ (SignatureScheme::RsaPssSha256
                | SignatureScheme::RsaPssSha384
                | SignatureScheme::RsaPssSha512
                | SignatureScheme::RsaPkcs1Sha256
                | SignatureScheme::RsaPkcs1Sha384
                | SignatureScheme::RsaPkcs1Sha512),
                Self::Rsa { modulus, exponent },
            ) => {
                let key = RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(modulus),
                    rsa::BigUint::from_bytes_be(exponent),
                )
                .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
                verify_rsa_message(algorithm, &key, message, signature)
            }
            _ => Err(SoftwareSigningError::AlgorithmMismatch),
        }
    }

    /// Verify a signature over a digest supplied by the caller.
    ///
    /// This is available for ECDSA and RSA. Ed25519 and ML-DSA define their
    /// own message processing and therefore use [`Self::verify_message`].
    pub fn verify_prehash(
        &self,
        algorithm: SignatureScheme,
        prehash: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        match (algorithm, self) {
            (
                SignatureScheme::EcdsaP224Sha224,
                Self::Ec {
                    curve: EcCurve::P224,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p224, uncompressed, prehash, signature),
            (
                SignatureScheme::EcdsaP256Sha256,
                Self::Ec {
                    curve: EcCurve::P256,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p256, uncompressed, prehash, signature),
            (
                SignatureScheme::EcdsaP384Sha384,
                Self::Ec {
                    curve: EcCurve::P384,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p384, uncompressed, prehash, signature),
            (
                SignatureScheme::EcdsaP521Sha512,
                Self::Ec {
                    curve: EcCurve::P521,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p521, uncompressed, prehash, signature),
            (
                SignatureScheme::EcdsaSecp256k1Sha256,
                Self::Ec {
                    curve: EcCurve::Secp256k1,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(k256, uncompressed, prehash, signature),
            (
                SignatureScheme::EcdsaBrainpoolP256Sha256,
                Self::Ec {
                    curve: EcCurve::BrainpoolP256,
                    uncompressed,
                },
            ) => verify_generic_ecdsa_prehash!(
                bp256::BrainpoolP256r1,
                uncompressed,
                prehash,
                signature
            ),
            (
                SignatureScheme::EcdsaBrainpoolP384Sha384,
                Self::Ec {
                    curve: EcCurve::BrainpoolP384,
                    uncompressed,
                },
            ) => verify_generic_ecdsa_prehash!(
                bp384::BrainpoolP384r1,
                uncompressed,
                prehash,
                signature
            ),
            (
                SignatureScheme::EcdsaBrainpoolP512Sha512,
                Self::Ec {
                    curve: EcCurve::BrainpoolP512,
                    uncompressed,
                },
            ) => crate::brainpool512::verify_prehash(uncompressed, prehash, signature)
                .map_err(|_| SoftwareSigningError::InvalidSignature),
            (
                algorithm @ (SignatureScheme::RsaPssSha256
                | SignatureScheme::RsaPssSha384
                | SignatureScheme::RsaPssSha512
                | SignatureScheme::RsaPkcs1Sha256
                | SignatureScheme::RsaPkcs1Sha384
                | SignatureScheme::RsaPkcs1Sha512),
                Self::Rsa { modulus, exponent },
            ) => {
                let key = rsa_public_key(modulus, exponent)?;
                verify_rsa_prehash(algorithm, &key, prehash, signature, None)
            }
            _ => Err(SoftwareSigningError::AlgorithmMismatch),
        }
    }

    /// Verify an RSA-PSS signature over a digest with an explicit salt length.
    pub fn verify_rsa_pss_prehash(
        &self,
        algorithm: SignatureScheme,
        prehash: &[u8],
        salt_length: usize,
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let key = rsa_public_key(modulus, exponent)?;
        verify_rsa_prehash(algorithm, &key, prehash, signature, Some(salt_length))
    }
}

fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, SoftwareSigningError> {
    RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| SoftwareSigningError::InvalidPublicKey)
}

fn rsa_profile(algorithm: SignatureScheme) -> Option<(RsaHashAlgorithm, bool)> {
    match algorithm {
        SignatureScheme::RsaPssSha256 => Some((RsaHashAlgorithm::Sha256, true)),
        SignatureScheme::RsaPssSha384 => Some((RsaHashAlgorithm::Sha384, true)),
        SignatureScheme::RsaPssSha512 => Some((RsaHashAlgorithm::Sha512, true)),
        SignatureScheme::RsaPkcs1Sha256 => Some((RsaHashAlgorithm::Sha256, false)),
        SignatureScheme::RsaPkcs1Sha384 => Some((RsaHashAlgorithm::Sha384, false)),
        SignatureScheme::RsaPkcs1Sha512 => Some((RsaHashAlgorithm::Sha512, false)),
        _ => None,
    }
}

fn verify_rsa_message(
    algorithm: SignatureScheme,
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SoftwareSigningError> {
    let (hash, _) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    verify_rsa_prehash(algorithm, key, &hash.digest(message), signature, None)
}

fn verify_rsa_prehash(
    algorithm: SignatureScheme,
    key: &RsaPublicKey,
    prehash: &[u8],
    signature: &[u8],
    pss_salt_length: Option<usize>,
) -> Result<(), SoftwareSigningError> {
    let (hash, pss) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    let result = if pss {
        rsa_verify_pss_digest(
            key,
            RsaPssParameters {
                hash,
                mgf_hash: hash,
                salt_length: pss_salt_length.unwrap_or_else(|| hash.output_length()),
            },
            prehash,
            signature,
        )
    } else {
        rsa_verify_pkcs1v15_digest(key, hash, prehash, signature)
    };
    result.map_err(map_rsa_verification_error)
}

fn map_rsa_verification_error(error: RsaConstructionError) -> SoftwareSigningError {
    match error {
        RsaConstructionError::InvalidKey => SoftwareSigningError::InvalidPublicKey,
        RsaConstructionError::InputTooLong
        | RsaConstructionError::InputOutOfRange
        | RsaConstructionError::InvalidDigestLength
        | RsaConstructionError::InvalidSignature
        | RsaConstructionError::RandomnessUnavailable
        | RsaConstructionError::OperationFailed => SoftwareSigningError::InvalidSignature,
    }
}

/// A signature in the algorithm's fixed-width native representation.
///
/// ECDSA values are the concatenated, fixed-width `r || s` form. Ed25519 and
/// ML-DSA values are their standard raw signature encodings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareSignature(Vec<u8>);

impl SoftwareSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Encode a fixed-width ECDSA signature as ASN.1 DER without requiring a
    /// private or public key implementation.
    pub fn to_ecdsa_der(&self, curve: EcCurve) -> Result<Vec<u8>, SoftwareSigningError> {
        macro_rules! encode {
            ($curve:ty) => {{
                ecdsa::Signature::<$curve>::from_slice(&self.0)
                    .map(|signature| signature.to_der().as_bytes().to_vec())
                    .map_err(|_| SoftwareSigningError::InvalidSignature)
            }};
        }
        match curve {
            EcCurve::P224 => encode!(p224::NistP224),
            EcCurve::P256 => encode!(p256::NistP256),
            EcCurve::P384 => encode!(p384::NistP384),
            EcCurve::P521 => encode!(p521::NistP521),
            EcCurve::Secp256k1 => encode!(k256::Secp256k1),
            EcCurve::BrainpoolP256 => encode!(bp256::BrainpoolP256r1),
            EcCurve::BrainpoolP384 => encode!(bp384::BrainpoolP384r1),
            EcCurve::BrainpoolP512 => encode!(BrainpoolP512r1),
        }
    }
}

fn der_length(encoded: &[u8], offset: &mut usize) -> Option<usize> {
    let first = *encoded.get(*offset)?;
    *offset += 1;
    match first {
        0..=0x7f => Some(first as usize),
        0x81 => {
            let length = *encoded.get(*offset)? as usize;
            *offset += 1;
            (length >= 0x80).then_some(length)
        }
        _ => None,
    }
}

fn der_positive_integer<'a>(encoded: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    if *encoded.get(*offset)? != 0x02 {
        return None;
    }
    *offset += 1;
    let length = der_length(encoded, offset)?;
    let value = encoded.get(*offset..offset.checked_add(length)?)?;
    *offset += length;
    if value.is_empty() || value[0] & 0x80 != 0 {
        return None;
    }
    if value.len() > 1 && value[0] == 0 {
        if value[1] & 0x80 == 0 {
            return None;
        }
        Some(&value[1..])
    } else {
        Some(value)
    }
}

/// Convert a canonical ASN.1 DER ECDSA signature to fixed-width `r || s`
/// without requiring a public or private key implementation.
pub fn ecdsa_signature_from_der(
    signature: &[u8],
    coordinate_length: usize,
) -> Result<Vec<u8>, SoftwareSigningError> {
    let invalid = || SoftwareSigningError::InvalidSignature;
    let mut offset = 0;
    if coordinate_length == 0 || signature.get(offset) != Some(&0x30) {
        return Err(invalid());
    }
    offset += 1;
    let sequence_length = der_length(signature, &mut offset).ok_or_else(invalid)?;
    if offset.checked_add(sequence_length) != Some(signature.len()) {
        return Err(invalid());
    }
    let r = der_positive_integer(signature, &mut offset).ok_or_else(invalid)?;
    let s = der_positive_integer(signature, &mut offset).ok_or_else(invalid)?;
    if offset != signature.len() || r.len() > coordinate_length || s.len() > coordinate_length {
        return Err(invalid());
    }
    let output_length = coordinate_length.checked_mul(2).ok_or_else(invalid)?;
    let mut output = vec![0; output_length];
    output[coordinate_length - r.len()..coordinate_length].copy_from_slice(r);
    output[output_length - s.len()..].copy_from_slice(s);
    Ok(output)
}

#[derive(Clone)]
pub enum SoftwareSigningKey {
    P224(P224SecretKey),
    P256(P256SecretKey),
    Ed25519(Ed25519SigningKey),
    P384(P384SecretKey),
    P521(P521SecretKey),
    K256(K256SecretKey),
    BrainpoolP256(BrainpoolP256SecretKey),
    BrainpoolP384(BrainpoolP384SecretKey),
    BrainpoolP512(BrainpoolP512SecretKey),
    Rsa(Box<RsaPrivateKey>),
    MlDsa(MlDsaPrivateKey),
}

// Every contained private-key implementation is built with its zeroization
// support enabled and clears its secret state on drop. Exposing the marker on
// the protocol-neutral wrapper lets runtime object stores preserve that
// guarantee without re-serializing the key.
impl ZeroizeOnDrop for SoftwareSigningKey {}

/// The identity of a private signing key at generation and import boundaries.
///
/// Unlike [`SignatureScheme`], this contains no padding or digest choice. RSA
/// size belongs here because it is a property of the key, not of an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyKind {
    Ec(EcCurve),
    Ed25519,
    Rsa { modulus_bits: usize },
    MlDsa(MlDsaParameterSet),
}

impl fmt::Debug for SoftwareSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareSigningKey")
            .field("kind", &self.kind_name())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigningKey {
    pub fn key_kind(&self) -> KeyKind {
        match self {
            Self::P224(_) => KeyKind::Ec(EcCurve::P224),
            Self::P256(_) => KeyKind::Ec(EcCurve::P256),
            Self::Ed25519(_) => KeyKind::Ed25519,
            Self::P384(_) => KeyKind::Ec(EcCurve::P384),
            Self::P521(_) => KeyKind::Ec(EcCurve::P521),
            Self::K256(_) => KeyKind::Ec(EcCurve::Secp256k1),
            Self::BrainpoolP256(_) => KeyKind::Ec(EcCurve::BrainpoolP256),
            Self::BrainpoolP384(_) => KeyKind::Ec(EcCurve::BrainpoolP384),
            Self::BrainpoolP512(_) => KeyKind::Ec(EcCurve::BrainpoolP512),
            Self::Rsa(key) => KeyKind::Rsa {
                modulus_bits: key.n().bits(),
            },
            Self::MlDsa(key) => KeyKind::MlDsa(key.parameter_set()),
        }
    }

    /// Raw private value used by token APIs. RSA private components have
    /// dedicated accessors and are intentionally not returned here.
    pub fn private_value(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Rsa(_) => None,
            Self::MlDsa(key) => Some(key.expanded_private_key()),
            _ => self.serialized().ok(),
        }
    }

    pub fn rsa_size(&self) -> Result<usize, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        Ok(key.size())
    }

    /// Export `d, p, q, dP, dQ, qInv` as unsigned big-endian integers.
    pub fn rsa_private_components(&self) -> Result<[Zeroizing<Vec<u8>>; 6], SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let [p, q] = key.primes() else {
            return Err(SoftwareSigningError::InvalidPrivateKey);
        };
        let dp = key.dp().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let dq = key.dq().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let qinv = key
            .qinv()
            .and_then(|value| value.to_biguint())
            .ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        Ok([
            Zeroizing::new(key.d().to_bytes_be()),
            Zeroizing::new(p.to_bytes_be()),
            Zeroizing::new(q.to_bytes_be()),
            Zeroizing::new(dp.to_bytes_be()),
            Zeroizing::new(dq.to_bytes_be()),
            Zeroizing::new(qinv.to_bytes_be()),
        ])
    }

    /// Import the PKCS#8 `PrivateKeyInfo` representation used by YubiHSM's
    /// RSA-wrapped asymmetric-key commands.
    pub fn from_pkcs8_der(
        algorithm: SignatureScheme,
        serialized: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        match algorithm {
            SignatureScheme::EcdsaP224Sha224 => {
                P224SecretKey::from_pkcs8_der(serialized).map(Self::P224)
            }
            SignatureScheme::EcdsaP256Sha256 => {
                P256SecretKey::from_pkcs8_der(serialized).map(Self::P256)
            }
            SignatureScheme::Ed25519 => {
                Ed25519SigningKey::from_pkcs8_der(serialized).map(Self::Ed25519)
            }
            SignatureScheme::EcdsaP384Sha384 => {
                P384SecretKey::from_pkcs8_der(serialized).map(Self::P384)
            }
            SignatureScheme::EcdsaP521Sha512 => {
                P521SecretKey::from_pkcs8_der(serialized).map(Self::P521)
            }
            SignatureScheme::EcdsaSecp256k1Sha256 => {
                K256SecretKey::from_pkcs8_der(serialized).map(Self::K256)
            }
            SignatureScheme::EcdsaBrainpoolP256Sha256 => {
                BrainpoolP256SecretKey::from_pkcs8_der(serialized).map(Self::BrainpoolP256)
            }
            SignatureScheme::EcdsaBrainpoolP384Sha384 => {
                BrainpoolP384SecretKey::from_pkcs8_der(serialized).map(Self::BrainpoolP384)
            }
            SignatureScheme::EcdsaBrainpoolP512Sha512 => {
                BrainpoolP512SecretKey::from_pkcs8_der(serialized).map(Self::BrainpoolP512)
            }
            SignatureScheme::RsaPssSha256
            | SignatureScheme::RsaPssSha384
            | SignatureScheme::RsaPssSha512
            | SignatureScheme::RsaPkcs1Sha256
            | SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPkcs1Sha512 => {
                let mut key = RsaPrivateKey::from_pkcs8_der(serialized)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                key.precompute()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                return Ok(Self::Rsa(Box::new(key)));
            }
            SignatureScheme::MlDsa(parameter_set) => {
                return MlDsaPrivateKey::from_pkcs8_der(parameter_set, serialized)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey);
            }
        }
        .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
    }

    /// Import a key using only key identity. Operation choices such as RSA
    /// padding are deliberately absent from this boundary.
    pub fn from_pkcs8_der_for_kind(
        kind: KeyKind,
        serialized: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        let key = match kind {
            KeyKind::Ec(curve) => Self::from_pkcs8_der(curve.signature_scheme(), serialized)?,
            KeyKind::Ed25519 => Self::from_pkcs8_der(SignatureScheme::Ed25519, serialized)?,
            KeyKind::Rsa { modulus_bits } => {
                let key = Self::from_pkcs8_der(SignatureScheme::RsaPssSha256, serialized)?;
                if key.rsa_size()?.checked_mul(8) != Some(modulus_bits) {
                    return Err(SoftwareSigningError::InvalidPrivateKey);
                }
                key
            }
            KeyKind::MlDsa(parameter_set) => {
                Self::from_pkcs8_der(SignatureScheme::MlDsa(parameter_set), serialized)?
            }
        };
        Ok(key)
    }

    /// Export the PKCS#8 `PrivateKeyInfo` representation used by YubiHSM's
    /// RSA-wrapped asymmetric-key commands.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, SoftwareSigningError> {
        let encoded = match self {
            Self::P224(key) => key.to_pkcs8_der(),
            Self::P256(key) => key.to_pkcs8_der(),
            Self::Ed25519(key) => key.to_pkcs8_der(),
            Self::P384(key) => key.to_pkcs8_der(),
            Self::P521(key) => key.to_pkcs8_der(),
            Self::K256(key) => key.to_pkcs8_der(),
            Self::BrainpoolP256(key) => key.to_pkcs8_der(),
            Self::BrainpoolP384(key) => key.to_pkcs8_der(),
            Self::BrainpoolP512(key) => key.to_pkcs8_der(),
            Self::Rsa(key) => {
                return key
                    .to_pkcs8_der()
                    .map(|value| Zeroizing::new(value.as_bytes().to_vec()))
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey);
            }
            Self::MlDsa(key) => {
                return key
                    .to_pkcs8_der()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
        }
        .map(|value| Zeroizing::new(value.as_bytes().to_vec()))
        .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        Ok(encoded)
    }

    pub fn generate(algorithm: SignatureScheme) -> Result<Self, SoftwareSigningError> {
        match algorithm {
            SignatureScheme::EcdsaP224Sha224 => random_p224_secret().map(Self::P224),
            SignatureScheme::EcdsaP256Sha256 => random_p256_secret().map(Self::P256),
            SignatureScheme::Ed25519 => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                getrandom::fill(seed.as_mut())
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
                Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(&seed)))
            }
            SignatureScheme::EcdsaP384Sha384 => random_p384_secret().map(Self::P384),
            SignatureScheme::EcdsaP521Sha512 => random_p521_secret().map(Self::P521),
            SignatureScheme::EcdsaSecp256k1Sha256 => random_k256_secret().map(Self::K256),
            SignatureScheme::EcdsaBrainpoolP256Sha256 => {
                random_brainpool_p256_secret().map(Self::BrainpoolP256)
            }
            SignatureScheme::EcdsaBrainpoolP384Sha384 => {
                random_brainpool_p384_secret().map(Self::BrainpoolP384)
            }
            SignatureScheme::EcdsaBrainpoolP512Sha512 => {
                random_brainpool_p512_secret().map(Self::BrainpoolP512)
            }
            SignatureScheme::RsaPssSha256
            | SignatureScheme::RsaPssSha384
            | SignatureScheme::RsaPssSha512
            | SignatureScheme::RsaPkcs1Sha256
            | SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPkcs1Sha512 => {
                let mut key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2_048)
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
                key.precompute()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Rsa(Box::new(key)))
            }
            SignatureScheme::MlDsa(parameter_set) => MlDsaPrivateKey::generate(parameter_set)
                .map(Self::MlDsa)
                .map_err(|_| SoftwareSigningError::RandomnessUnavailable),
        }
    }

    /// Generate a private key without selecting a signing operation.
    pub fn generate_for_kind(kind: KeyKind) -> Result<Self, SoftwareSigningError> {
        match kind {
            KeyKind::Ec(curve) => Self::generate(curve.signature_scheme()),
            KeyKind::Ed25519 => Self::generate(SignatureScheme::Ed25519),
            KeyKind::Rsa { modulus_bits } => Self::generate_rsa(modulus_bits),
            KeyKind::MlDsa(parameter_set) => Self::generate(SignatureScheme::MlDsa(parameter_set)),
        }
    }

    /// Generate an RSA key with an explicit modulus size.
    pub fn generate_rsa(modulus_bits: usize) -> Result<Self, SoftwareSigningError> {
        let mut key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, modulus_bits)
            .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        key.precompute()
            .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    /// Reconstruct an RSA private key from its two primes and public exponent.
    pub fn from_rsa_primes(
        p: &[u8],
        q: &[u8],
        public_exponent: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        let mut key = RsaPrivateKey::from_p_q(
            rsa::BigUint::from_bytes_be(p),
            rsa::BigUint::from_bytes_be(q),
            rsa::BigUint::from_bytes_be(public_exponent),
        )
        .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        key.precompute()
            .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    pub fn from_serialized(
        algorithm: SignatureScheme,
        serialized: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        match algorithm {
            SignatureScheme::EcdsaP224Sha224 => P224SecretKey::from_slice(serialized)
                .map(Self::P224)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SignatureScheme::EcdsaP256Sha256 => P256SecretKey::from_slice(serialized)
                .map(Self::P256)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SignatureScheme::Ed25519 => {
                let seed = serialized
                    .try_into()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(seed)))
            }
            SignatureScheme::EcdsaP384Sha384 => P384SecretKey::from_slice(serialized)
                .map(Self::P384)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SignatureScheme::EcdsaP521Sha512 => P521SecretKey::from_slice(serialized)
                .map(Self::P521)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SignatureScheme::EcdsaSecp256k1Sha256 => K256SecretKey::from_slice(serialized)
                .map(Self::K256)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SignatureScheme::EcdsaBrainpoolP256Sha256 => {
                BrainpoolP256SecretKey::from_slice(serialized)
                    .map(Self::BrainpoolP256)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
            SignatureScheme::EcdsaBrainpoolP384Sha384 => {
                BrainpoolP384SecretKey::from_slice(serialized)
                    .map(Self::BrainpoolP384)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
            SignatureScheme::EcdsaBrainpoolP512Sha512 => {
                BrainpoolP512SecretKey::from_slice(serialized)
                    .map(Self::BrainpoolP512)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
            SignatureScheme::RsaPssSha256
            | SignatureScheme::RsaPssSha384
            | SignatureScheme::RsaPssSha512
            | SignatureScheme::RsaPkcs1Sha256
            | SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPkcs1Sha512 => {
                let mut key = RsaPrivateKey::from_pkcs8_der(serialized)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                key.precompute()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Rsa(Box::new(key)))
            }
            SignatureScheme::MlDsa(parameter_set) => {
                MlDsaPrivateKey::from_seed_slice(parameter_set, serialized)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
        }
    }

    /// Restore a compact private value using only key identity.
    pub fn from_serialized_for_kind(
        kind: KeyKind,
        serialized: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        let key = match kind {
            KeyKind::Ec(curve) => Self::from_serialized(curve.signature_scheme(), serialized)?,
            KeyKind::Ed25519 => Self::from_serialized(SignatureScheme::Ed25519, serialized)?,
            KeyKind::Rsa { modulus_bits } => {
                let key = Self::from_serialized(SignatureScheme::RsaPssSha256, serialized)?;
                if key.rsa_size()?.checked_mul(8) != Some(modulus_bits) {
                    return Err(SoftwareSigningError::InvalidPrivateKey);
                }
                key
            }
            KeyKind::MlDsa(parameter_set) => {
                Self::from_serialized(SignatureScheme::MlDsa(parameter_set), serialized)?
            }
        };
        Ok(key)
    }

    const fn kind_name(&self) -> &'static str {
        match self {
            Self::P224(_) => "P-224",
            Self::P256(_) => "P-256",
            Self::Ed25519(_) => "Ed25519",
            Self::P384(_) => "P-384",
            Self::P521(_) => "P-521",
            Self::K256(_) => "secp256k1",
            Self::BrainpoolP256(_) => "brainpoolP256r1",
            Self::BrainpoolP384(_) => "brainpoolP384r1",
            Self::BrainpoolP512(_) => "brainpoolP512r1",
            Self::Rsa(_) => "RSA",
            Self::MlDsa(_) => "ML-DSA",
        }
    }

    pub fn serialized(&self) -> Result<Zeroizing<Vec<u8>>, SoftwareSigningError> {
        let serialized = match self {
            Self::P224(key) => key.to_bytes().to_vec(),
            Self::P256(key) => key.to_bytes().to_vec(),
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::P384(key) => key.to_bytes().to_vec(),
            Self::P521(key) => key.to_bytes().to_vec(),
            Self::K256(key) => key.to_bytes().to_vec(),
            Self::BrainpoolP256(key) => key.to_bytes().to_vec(),
            Self::BrainpoolP384(key) => key.to_bytes().to_vec(),
            Self::BrainpoolP512(key) => key.to_bytes().to_vec(),
            Self::Rsa(key) => key
                .to_pkcs8_der()
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?
                .as_bytes()
                .to_vec(),
            Self::MlDsa(key) => key.seed().to_vec(),
        };
        Ok(Zeroizing::new(serialized))
    }

    pub fn public_key(&self) -> SoftwarePublicKey {
        match self {
            Self::P224(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P224,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::P256(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::Ed25519(key) => SoftwarePublicKey::Ed25519(key.verifying_key().to_bytes()),
            Self::P384(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P384,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::P521(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P521,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::K256(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::Secp256k1,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::BrainpoolP256(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::BrainpoolP256,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::BrainpoolP384(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::BrainpoolP384,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::BrainpoolP512(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::BrainpoolP512,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::Rsa(key) => SoftwarePublicKey::Rsa {
                modulus: key.n().to_bytes_be(),
                exponent: key.e().to_bytes_be(),
            },
            Self::MlDsa(key) => SoftwarePublicKey::MlDsa {
                parameter_set: key.parameter_set(),
                public_key: key.public_key(),
            },
        }
    }

    pub fn sign_message(
        &self,
        algorithm: SignatureScheme,
        message: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let signature = match (algorithm, self) {
            (SignatureScheme::EcdsaP224Sha224, Self::P224(key)) => {
                let signature: p224::ecdsa::Signature =
                    p224::ecdsa::SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaP256Sha256, Self::P256(key)) => {
                let signature: p256::ecdsa::Signature =
                    P256SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::Ed25519, Self::Ed25519(key)) => key.sign(message).to_bytes().to_vec(),
            (SignatureScheme::EcdsaP384Sha384, Self::P384(key)) => {
                let signature: p384::ecdsa::Signature =
                    P384SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaP521Sha512, Self::P521(key)) => {
                let signature: p521::ecdsa::Signature =
                    P521SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaSecp256k1Sha256, Self::K256(key)) => {
                let signature: k256::ecdsa::Signature =
                    K256SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaBrainpoolP256Sha256, Self::BrainpoolP256(key)) => {
                let signature: ecdsa::Signature<bp256::BrainpoolP256r1> =
                    ecdsa::SigningKey::<bp256::BrainpoolP256r1>::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaBrainpoolP384Sha384, Self::BrainpoolP384(key)) => {
                let signature: ecdsa::Signature<bp384::BrainpoolP384r1> =
                    ecdsa::SigningKey::<bp384::BrainpoolP384r1>::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SignatureScheme::EcdsaBrainpoolP512Sha512, Self::BrainpoolP512(key)) => {
                let signature: crate::brainpool512::Signature =
                    ecdsa::SigningKey::<BrainpoolP512r1>::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (algorithm, Self::Rsa(key)) if algorithm.is_rsa() => {
                rsa_sign_message(algorithm, key, message)?
            }
            (SignatureScheme::MlDsa(parameter_set), Self::MlDsa(key))
                if parameter_set == key.parameter_set() =>
            {
                key.sign_hedged(message, &[])
                    .map_err(|_| SoftwareSigningError::SigningFailed)?
            }
            _ => return Err(SoftwareSigningError::AlgorithmMismatch),
        };
        Ok(SoftwareSignature(signature))
    }

    /// Sign a digest supplied by the caller.
    ///
    /// This is available for ECDSA and RSA. Ed25519 and ML-DSA define their
    /// own message processing and therefore use [`Self::sign_message`].
    pub fn sign_prehash(
        &self,
        algorithm: SignatureScheme,
        prehash: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        macro_rules! sign_ecdsa_prehash {
            ($key:expr, $signing_key:ty, $signature:ty) => {{
                let key = <$signing_key>::from($key.clone());
                let signature: $signature = key
                    .sign_prehash(prehash)
                    .map_err(|_| SoftwareSigningError::SigningFailed)?;
                signature.to_bytes().to_vec()
            }};
        }
        let signature = match (algorithm, self) {
            (SignatureScheme::EcdsaP224Sha224, Self::P224(key)) => {
                sign_ecdsa_prehash!(key, p224::ecdsa::SigningKey, p224::ecdsa::Signature)
            }
            (SignatureScheme::EcdsaP256Sha256, Self::P256(key)) => {
                sign_ecdsa_prehash!(key, P256SigningKey, p256::ecdsa::Signature)
            }
            (SignatureScheme::EcdsaP384Sha384, Self::P384(key)) => {
                sign_ecdsa_prehash!(key, P384SigningKey, p384::ecdsa::Signature)
            }
            (SignatureScheme::EcdsaP521Sha512, Self::P521(key)) => {
                sign_ecdsa_prehash!(key, P521SigningKey, p521::ecdsa::Signature)
            }
            (SignatureScheme::EcdsaSecp256k1Sha256, Self::K256(key)) => {
                sign_ecdsa_prehash!(key, K256SigningKey, k256::ecdsa::Signature)
            }
            (SignatureScheme::EcdsaBrainpoolP256Sha256, Self::BrainpoolP256(key)) => {
                sign_ecdsa_prehash!(
                    key,
                    ecdsa::SigningKey<bp256::BrainpoolP256r1>,
                    ecdsa::Signature<bp256::BrainpoolP256r1>
                )
            }
            (SignatureScheme::EcdsaBrainpoolP384Sha384, Self::BrainpoolP384(key)) => {
                sign_ecdsa_prehash!(
                    key,
                    ecdsa::SigningKey<bp384::BrainpoolP384r1>,
                    ecdsa::Signature<bp384::BrainpoolP384r1>
                )
            }
            (SignatureScheme::EcdsaBrainpoolP512Sha512, Self::BrainpoolP512(key)) => {
                sign_ecdsa_prehash!(
                    key,
                    ecdsa::SigningKey<BrainpoolP512r1>,
                    crate::brainpool512::Signature
                )
            }
            (algorithm, Self::Rsa(key)) if algorithm.is_rsa() => {
                rsa_sign_prehash(algorithm, key, prehash, None)?
            }
            _ => return Err(SoftwareSigningError::AlgorithmMismatch),
        };
        Ok(SoftwareSignature(signature))
    }

    /// Sign a digest with RSA-PSS and a caller-selected salt length.
    pub fn sign_rsa_pss_prehash(
        &self,
        algorithm: SignatureScheme,
        prehash: &[u8],
        salt_length: usize,
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_prehash(algorithm, key, prehash, Some(salt_length)).map(SoftwareSignature)
    }

    /// Sign caller-supplied PKCS #1 v1.5 payload bytes. The protocol layer may
    /// pass either a DigestInfo value or another explicitly encoded payload.
    pub fn sign_rsa_pkcs1v15_payload(
        &self,
        payload: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_pkcs1v15_payload(key, payload)
            .map(SoftwareSignature)
            .map_err(map_rsa_signing_error)
    }

    /// Sign a digest after applying the selected PKCS #1 DigestInfo prefix.
    pub fn sign_rsa_pkcs1v15_digest(
        &self,
        hash: RsaHashAlgorithm,
        digest: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_pkcs1v15_digest(key, hash, digest)
            .map(SoftwareSignature)
            .map_err(map_rsa_signing_error)
    }

    /// Sign a digest with independently selected message and MGF1 hashes.
    pub fn sign_rsa_pss_digest(
        &self,
        hash: RsaHashAlgorithm,
        mgf_hash: RsaHashAlgorithm,
        salt_length: usize,
        digest: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_pss_digest(
            key,
            RsaPssParameters {
                hash,
                mgf_hash,
                salt_length,
            },
            digest,
        )
        .map(SoftwareSignature)
        .map_err(map_rsa_signing_error)
    }

    pub fn decrypt_rsa_pkcs1v15(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_decrypt_pkcs1v15(key, ciphertext)
            .map(Zeroizing::new)
            .map_err(map_rsa_signing_error)
    }

    pub fn decrypt_rsa_oaep_digest(
        &self,
        ciphertext: &[u8],
        label_digest: &[u8],
        mgf_hash: RsaHashAlgorithm,
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_decrypt_oaep_digest(key, ciphertext, label_digest, mgf_hash)
            .map(Zeroizing::new)
            .map_err(map_rsa_signing_error)
    }

    /// Perform the raw RSA private-key operation used by protocols that supply
    /// their own modulus-width encoding.
    pub fn sign_rsa_raw(&self, input: &[u8]) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_raw(key, input)
            .map(SoftwareSignature)
            .map_err(map_rsa_signing_error)
    }

    /// Export the two primes and precomputed CRT values as unsigned big-endian
    /// integers in P, Q, dP, dQ, QInv order.
    pub fn rsa_crt_components(&self) -> Result<[Zeroizing<Vec<u8>>; 5], SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let [p, q] = key.primes() else {
            return Err(SoftwareSigningError::InvalidPrivateKey);
        };
        let dp = key.dp().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let dq = key.dq().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let qinv = key
            .qinv()
            .and_then(|value| value.to_biguint())
            .ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        Ok([
            Zeroizing::new(p.to_bytes_be()),
            Zeroizing::new(q.to_bytes_be()),
            Zeroizing::new(dp.to_bytes_be()),
            Zeroizing::new(dq.to_bytes_be()),
            Zeroizing::new(qinv.to_bytes_be()),
        ])
    }
}

fn rsa_sign_message(
    algorithm: SignatureScheme,
    key: &RsaPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, SoftwareSigningError> {
    let (hash, _) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    rsa_sign_prehash(algorithm, key, &hash.digest(message), None)
}

fn rsa_sign_prehash(
    algorithm: SignatureScheme,
    key: &RsaPrivateKey,
    prehash: &[u8],
    pss_salt_length: Option<usize>,
) -> Result<Vec<u8>, SoftwareSigningError> {
    let (hash, pss) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    let result = if pss {
        rsa_sign_pss_digest(
            key,
            RsaPssParameters {
                hash,
                mgf_hash: hash,
                salt_length: pss_salt_length.unwrap_or_else(|| hash.output_length()),
            },
            prehash,
        )
    } else {
        rsa_sign_pkcs1v15_digest(key, hash, prehash)
    };
    result.map_err(map_rsa_signing_error)
}

fn map_rsa_signing_error(error: RsaConstructionError) -> SoftwareSigningError {
    match error {
        RsaConstructionError::InvalidKey => SoftwareSigningError::InvalidPrivateKey,
        RsaConstructionError::RandomnessUnavailable => SoftwareSigningError::RandomnessUnavailable,
        RsaConstructionError::InputTooLong
        | RsaConstructionError::InputOutOfRange
        | RsaConstructionError::InvalidDigestLength
        | RsaConstructionError::InvalidSignature
        | RsaConstructionError::OperationFailed => SoftwareSigningError::SigningFailed,
    }
}

fn random_p256_secret() -> Result<P256SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P256SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_p224_secret() -> Result<P224SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 28]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P224SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_p384_secret() -> Result<P384SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 48]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P384SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_p521_secret() -> Result<P521SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 66]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P521SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_k256_secret() -> Result<K256SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = K256SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_brainpool_p256_secret() -> Result<BrainpoolP256SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = BrainpoolP256SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_brainpool_p384_secret() -> Result<BrainpoolP384SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 48]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = BrainpoolP384SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_brainpool_p512_secret() -> Result<BrainpoolP512SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 64]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = BrainpoolP512SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    #[test]
    fn every_key_kind_round_trips_compact_private_material() {
        for algorithm in [
            SignatureScheme::EcdsaP224Sha224,
            SignatureScheme::EcdsaP256Sha256,
            SignatureScheme::Ed25519,
            SignatureScheme::EcdsaP384Sha384,
            SignatureScheme::EcdsaP521Sha512,
            SignatureScheme::EcdsaSecp256k1Sha256,
            SignatureScheme::EcdsaBrainpoolP256Sha256,
            SignatureScheme::EcdsaBrainpoolP384Sha384,
            SignatureScheme::RsaPssSha256,
            SignatureScheme::MlDsa(MlDsaParameterSet::MlDsa44),
            SignatureScheme::MlDsa(MlDsaParameterSet::MlDsa65),
            SignatureScheme::MlDsa(MlDsaParameterSet::MlDsa87),
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let serialized = key.serialized().unwrap();
            let restored = SoftwareSigningKey::from_serialized(algorithm, &serialized).unwrap();
            let public_key = key.public_key();
            assert_eq!(restored.public_key(), public_key);
            let signature = restored
                .sign_message(algorithm, b"shared signing test")
                .unwrap();
            public_key
                .verify_message(algorithm, b"shared signing test", signature.as_bytes())
                .unwrap();
            assert_eq!(
                public_key.verify_message(algorithm, b"changed", signature.as_bytes()),
                Err(SoftwareSigningError::InvalidSignature)
            );
        }
    }

    #[test]
    fn every_classical_asymmetric_key_round_trips_pkcs8() {
        for algorithm in [
            SignatureScheme::EcdsaP224Sha224,
            SignatureScheme::EcdsaP256Sha256,
            SignatureScheme::Ed25519,
            SignatureScheme::EcdsaP384Sha384,
            SignatureScheme::EcdsaP521Sha512,
            SignatureScheme::EcdsaSecp256k1Sha256,
            SignatureScheme::EcdsaBrainpoolP256Sha256,
            SignatureScheme::EcdsaBrainpoolP384Sha384,
            SignatureScheme::EcdsaBrainpoolP512Sha512,
            SignatureScheme::RsaPssSha256,
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let encoded = key.to_pkcs8_der().unwrap();
            let restored = SoftwareSigningKey::from_pkcs8_der(algorithm, &encoded).unwrap();
            assert_eq!(restored.public_key(), key.public_key());
        }
    }

    #[test]
    fn ecdsa_keys_sign_and_verify_caller_supplied_digests() {
        for (algorithm, prehash) in [
            (SignatureScheme::EcdsaP224Sha224, vec![0x22; 28]),
            (
                SignatureScheme::EcdsaP256Sha256,
                Sha256::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaP384Sha384,
                Sha384::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaP521Sha512,
                Sha512::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaSecp256k1Sha256,
                Sha256::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaBrainpoolP256Sha256,
                Sha256::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaBrainpoolP384Sha384,
                Sha384::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SignatureScheme::EcdsaBrainpoolP512Sha512,
                Sha512::digest(b"prehashed signing test").to_vec(),
            ),
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let public_key = key.public_key();
            let signature = key.sign_prehash(algorithm, &prehash).unwrap();
            let der = signature
                .to_ecdsa_der(algorithm.ec_curve().unwrap())
                .unwrap();
            assert_eq!(der.first(), Some(&0x30));
            assert_eq!(
                ecdsa_signature_from_der(&der, signature.as_bytes().len() / 2).unwrap(),
                signature.as_bytes()
            );
            public_key
                .verify_prehash(algorithm, &prehash, signature.as_bytes())
                .unwrap();
            let mut changed = prehash;
            changed[0] ^= 1;
            assert_eq!(
                public_key.verify_prehash(algorithm, &changed, signature.as_bytes()),
                Err(SoftwareSigningError::InvalidSignature)
            );
        }
    }

    #[test]
    fn brainpool_p512_private_material_round_trips_and_signs_prehashes() {
        let algorithm = SignatureScheme::EcdsaBrainpoolP512Sha512;
        let key = SoftwareSigningKey::generate(algorithm).unwrap();
        let serialized = key.serialized().unwrap();
        let restored = SoftwareSigningKey::from_serialized(algorithm, &serialized).unwrap();
        assert_eq!(restored.public_key(), key.public_key());
        let digest = [0x51; 64];
        let signature = restored.sign_prehash(algorithm, &digest).unwrap();
        assert_eq!(signature.as_bytes().len(), 128);
        restored
            .public_key()
            .verify_prehash(algorithm, &digest, signature.as_bytes())
            .unwrap();
    }

    #[test]
    fn rsa_keys_sign_and_verify_caller_supplied_digests() {
        let original = SoftwareSigningKey::generate(SignatureScheme::RsaPssSha256)
            .unwrap()
            .serialized()
            .unwrap();
        for (algorithm, digest_length) in [
            (SignatureScheme::RsaPssSha256, 32),
            (SignatureScheme::RsaPssSha384, 48),
            (SignatureScheme::RsaPssSha512, 64),
            (SignatureScheme::RsaPkcs1Sha256, 32),
            (SignatureScheme::RsaPkcs1Sha384, 48),
            (SignatureScheme::RsaPkcs1Sha512, 64),
        ] {
            let key = SoftwareSigningKey::from_serialized(algorithm, &original).unwrap();
            let public_key = key.public_key();
            let prehash = vec![0x5a; digest_length];
            let signature = key.sign_prehash(algorithm, &prehash).unwrap();
            public_key
                .verify_prehash(algorithm, &prehash, signature.as_bytes())
                .unwrap();
        }
    }

    #[test]
    fn rsa_pss_accepts_an_explicit_salt_length() {
        let algorithm = SignatureScheme::RsaPssSha256;
        let key = SoftwareSigningKey::generate(algorithm).unwrap();
        let public_key = key.public_key();
        let prehash = [0x73; 32];
        let signature = key.sign_rsa_pss_prehash(algorithm, &prehash, 17).unwrap();
        public_key
            .verify_rsa_pss_prehash(algorithm, &prehash, 17, signature.as_bytes())
            .unwrap();
        assert_eq!(
            public_key.verify_rsa_pss_prehash(algorithm, &prehash, 16, signature.as_bytes()),
            Err(SoftwareSigningError::InvalidSignature)
        );
    }

    #[test]
    fn explicit_rsa_sizes_and_prime_import_support_raw_operations() {
        let key = SoftwareSigningKey::generate_rsa(1_024).unwrap();
        let public_key = key.public_key();
        let mut input = vec![0; 128];
        input[1] = 1;
        input[127] = 0x42;
        let signature = key.sign_rsa_raw(&input).unwrap();
        public_key
            .verify_rsa_raw(&input, signature.as_bytes())
            .unwrap();

        let SoftwareSigningKey::Rsa(key) = &key else {
            unreachable!();
        };
        let rebuilt = SoftwareSigningKey::from_rsa_primes(
            &key.primes()[0].to_bytes_be(),
            &key.primes()[1].to_bytes_be(),
            &[1, 0, 1],
        )
        .unwrap();
        assert_eq!(rebuilt.public_key(), public_key);
        let signature = rebuilt.sign_rsa_raw(&input).unwrap();
        public_key
            .verify_rsa_raw(&input, signature.as_bytes())
            .unwrap();
    }

    #[test]
    fn rsa_pkcs1_and_oaep_encryption_round_trip() {
        let key = SoftwareSigningKey::generate_rsa(1_024).unwrap();
        let public = key.public_key();
        let plaintext = b"encrypted protocol payload";
        let ciphertext = public.encrypt_rsa_pkcs1v15(plaintext).unwrap();
        assert_eq!(
            key.decrypt_rsa_pkcs1v15(&ciphertext).unwrap().as_slice(),
            plaintext
        );

        let label_digest = RsaHashAlgorithm::Sha256.digest(b"label");
        let ciphertext = public
            .encrypt_rsa_oaep_digest(plaintext, &label_digest, RsaHashAlgorithm::Sha384)
            .unwrap();
        assert_eq!(
            key.decrypt_rsa_oaep_digest(&ciphertext, &label_digest, RsaHashAlgorithm::Sha384)
                .unwrap()
                .as_slice(),
            plaintext
        );
    }

    #[test]
    fn signing_keys_reject_malformed_material_and_algorithm_mismatches() {
        for algorithm in [
            SignatureScheme::EcdsaP224Sha224,
            SignatureScheme::EcdsaP256Sha256,
            SignatureScheme::Ed25519,
            SignatureScheme::EcdsaP384Sha384,
            SignatureScheme::EcdsaP521Sha512,
            SignatureScheme::EcdsaSecp256k1Sha256,
            SignatureScheme::EcdsaBrainpoolP256Sha256,
            SignatureScheme::EcdsaBrainpoolP384Sha384,
            SignatureScheme::EcdsaBrainpoolP512Sha512,
            SignatureScheme::RsaPssSha256,
            SignatureScheme::MlDsa(MlDsaParameterSet::MlDsa44),
        ] {
            assert!(matches!(
                SoftwareSigningKey::from_serialized(algorithm, &[0; 1]),
                Err(SoftwareSigningError::InvalidPrivateKey)
            ));
        }

        let ed25519 = SoftwareSigningKey::generate(SignatureScheme::Ed25519).unwrap();
        assert_eq!(
            ed25519.sign_prehash(SignatureScheme::EcdsaP256Sha256, &[0; 32]),
            Err(SoftwareSigningError::AlgorithmMismatch)
        );
        assert_eq!(
            ed25519.rsa_size(),
            Err(SoftwareSigningError::AlgorithmMismatch)
        );

        let p256 = SoftwareSigningKey::generate(SignatureScheme::EcdsaP256Sha256).unwrap();
        assert_eq!(
            p256.sign_message(SignatureScheme::Ed25519, b"message"),
            Err(SoftwareSigningError::AlgorithmMismatch)
        );
    }

    #[test]
    fn ecdsa_der_conversion_rejects_noncanonical_and_trailing_encodings() {
        for (signature, coordinate_length) in [
            (Vec::new(), 32),
            (vec![0x30, 0], 0),
            (vec![0x31, 0], 32),
            (vec![0x30, 6, 2, 1, 0x80, 2, 1, 1], 32),
            (vec![0x30, 6, 2, 1, 1, 2, 1, 1, 0], 32),
            (vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1], 32),
        ] {
            assert_eq!(
                ecdsa_signature_from_der(&signature, coordinate_length),
                Err(SoftwareSigningError::InvalidSignature)
            );
        }
    }
}
