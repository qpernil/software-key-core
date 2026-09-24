//! X.509 signing adapters for protocol-neutral software keys.
//!
//! This module owns standard public-key container and certificate-signature
//! encoding. Callers continue to own certificate profiles, names, extensions,
//! validity policy, serial-number policy, and trust decisions.

use crate::{
    post_quantum::ml_dsa_public_key_info,
    software_signing::{
        EcCurve, EdwardsCurve, SignatureScheme, SoftwarePublicKey, SoftwareSigningKey,
    },
};
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode,
    asn1::{Any, BitString},
};
use rsa::{BigUint, RsaPublicKey, pkcs8::EncodePublicKey as EncodeRsaPublicKey};
use signature::{Keypair, Signer};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};

/// A key or encoding cannot be represented by the supported X.509 adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X509SigningError;

impl std::fmt::Display for X509SigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("X.509 signing failed")
    }
}

impl std::error::Error for X509SigningError {}

/// An X.509-compatible signer backed by a [`SoftwareSigningKey`].
pub struct CertificateSigner {
    key: SoftwareSigningKey,
    verifying_key: CertificateVerifyingKey,
    scheme: SignatureScheme,
}

impl CertificateSigner {
    /// Adapt a supported software key for certificate signing.
    pub fn from_key(key: &SoftwareSigningKey) -> Result<Self, X509SigningError> {
        let public_key = key.public_key();
        let scheme = match &public_key {
            SoftwarePublicKey::Ec { curve, .. } => curve.signature_scheme(),
            SoftwarePublicKey::Edwards { curve, .. } => curve.signature_scheme(),
            SoftwarePublicKey::Rsa { .. } => SignatureScheme::RsaPkcs1Sha256,
            SoftwarePublicKey::MlDsa { .. } => return Err(X509SigningError),
        };
        Ok(Self {
            key: key.clone(),
            verifying_key: CertificateVerifyingKey(subject_public_key_info(&public_key)?),
            scheme,
        })
    }
}

/// The public-key half of [`CertificateSigner`].
#[derive(Clone)]
pub struct CertificateVerifyingKey(SubjectPublicKeyInfoOwned);

impl spki::EncodePublicKey for CertificateVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        spki::Document::try_from(self.0.to_der()?).map_err(Into::into)
    }
}

impl Keypair for CertificateSigner {
    type VerifyingKey = CertificateVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for CertificateSigner {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        let (oid, parameters) = match self.scheme {
            SignatureScheme::EcdsaP224Sha224 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1"), None)
            }
            SignatureScheme::EcdsaP256Sha256
            | SignatureScheme::EcdsaSecp256k1Sha256
            | SignatureScheme::EcdsaBrainpoolP256Sha256 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), None)
            }
            SignatureScheme::EcdsaP384Sha384 | SignatureScheme::EcdsaBrainpoolP384Sha384 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), None)
            }
            SignatureScheme::EcdsaP521Sha512 | SignatureScheme::EcdsaBrainpoolP512Sha512 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"), None)
            }
            SignatureScheme::Ed25519 => (ObjectIdentifier::new_unwrap("1.3.101.112"), None),
            SignatureScheme::Ed448 => (ObjectIdentifier::new_unwrap("1.3.101.113"), None),
            SignatureScheme::RsaPkcs1Sha256 => (
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                Some(Any::null()),
            ),
            SignatureScheme::RsaPssSha256
            | SignatureScheme::RsaPssSha384
            | SignatureScheme::RsaPssSha512
            | SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPkcs1Sha512
            | SignatureScheme::MlDsa(_) => return Err(spki::Error::KeyMalformed),
        };
        Ok(AlgorithmIdentifierOwned { oid, parameters })
    }
}

/// DER or raw signature bytes encoded as an X.509 BIT STRING.
pub struct CertificateSignature(Vec<u8>);

impl SignatureBitStringEncoding for CertificateSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

impl Signer<CertificateSignature> for CertificateSigner {
    fn try_sign(
        &self,
        message: &[u8],
    ) -> core::result::Result<CertificateSignature, signature::Error> {
        let signature = self
            .key
            .sign_message(self.scheme, message)
            .map_err(|_| signature::Error::new())?;
        let encoded = if let Some(curve) = self.scheme.ec_curve() {
            signature
                .to_ecdsa_der(curve)
                .map_err(|_| signature::Error::new())?
        } else {
            signature.into_bytes()
        };
        Ok(CertificateSignature(encoded))
    }
}

/// Convert a software public key to the standard X.509 SubjectPublicKeyInfo form.
pub fn subject_public_key_info(
    key: &SoftwarePublicKey,
) -> Result<SubjectPublicKeyInfoOwned, X509SigningError> {
    match key {
        SoftwarePublicKey::Ec {
            curve,
            uncompressed,
        } => ec_subject_public_key_info(*curve, uncompressed),
        SoftwarePublicKey::Edwards { curve, public_key } => {
            let oid = match curve {
                EdwardsCurve::Ed25519 => ObjectIdentifier::new_unwrap("1.3.101.112"),
                EdwardsCurve::Ed448 => ObjectIdentifier::new_unwrap("1.3.101.113"),
            };
            Ok(SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(public_key)
                    .map_err(|_| X509SigningError)?,
            })
        }
        SoftwarePublicKey::Rsa { modulus, exponent } => {
            let public = RsaPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent),
            )
            .map_err(|_| X509SigningError)?;
            let encoded = public.to_public_key_der().map_err(|_| X509SigningError)?;
            SubjectPublicKeyInfoOwned::from_der(encoded.as_bytes()).map_err(|_| X509SigningError)
        }
        SoftwarePublicKey::MlDsa {
            parameter_set,
            public_key,
        } => SubjectPublicKeyInfoOwned::from_der(
            &ml_dsa_public_key_info(*parameter_set, public_key).map_err(|_| X509SigningError)?,
        )
        .map_err(|_| X509SigningError),
    }
}

fn ec_subject_public_key_info(
    curve: EcCurve,
    uncompressed: &[u8],
) -> Result<SubjectPublicKeyInfoOwned, X509SigningError> {
    let curve_oid = match curve {
        EcCurve::P224 => "1.3.132.0.33",
        EcCurve::P256 => "1.2.840.10045.3.1.7",
        EcCurve::P384 => "1.3.132.0.34",
        EcCurve::P521 => "1.3.132.0.35",
        EcCurve::Secp256k1 => "1.3.132.0.10",
        EcCurve::BrainpoolP256 => "1.3.36.3.3.2.8.1.1.7",
        EcCurve::BrainpoolP384 => "1.3.36.3.3.2.8.1.1.11",
        EcCurve::BrainpoolP512 => "1.3.36.3.3.2.8.1.1.13",
    };
    let curve_oid = ObjectIdentifier::new(curve_oid).map_err(|_| X509SigningError)?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(Any::encode_from(&curve_oid).map_err(|_| X509SigningError)?),
        },
        subject_public_key: BitString::from_bytes(uncompressed).map_err(|_| X509SigningError)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_signing::{KeyKind, ecdsa_signature_from_der};

    #[test]
    fn supported_key_families_have_standard_spki_and_signature_algorithms() {
        let cases = [
            (
                KeyKind::Ec(EcCurve::P256),
                "1.2.840.10045.2.1",
                "1.2.840.10045.4.3.2",
            ),
            (
                KeyKind::Ec(EcCurve::P384),
                "1.2.840.10045.2.1",
                "1.2.840.10045.4.3.3",
            ),
            (
                KeyKind::Edwards(EdwardsCurve::Ed25519),
                "1.3.101.112",
                "1.3.101.112",
            ),
            (
                KeyKind::Rsa { modulus_bits: 1024 },
                "1.2.840.113549.1.1.1",
                "1.2.840.113549.1.1.11",
            ),
        ];

        for (kind, public_oid, signature_oid) in cases {
            let key = SoftwareSigningKey::generate_for_kind(kind).unwrap();
            let info = subject_public_key_info(&key.public_key()).unwrap();
            assert_eq!(info.algorithm.oid.to_string(), public_oid);
            let signer = CertificateSigner::from_key(&key).unwrap();
            assert_eq!(
                signer
                    .signature_algorithm_identifier()
                    .unwrap()
                    .oid
                    .to_string(),
                signature_oid
            );
        }
    }

    #[test]
    fn certificate_signer_emits_der_ecdsa_signatures() {
        let key = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let signer = CertificateSigner::from_key(&key).unwrap();
        let message = b"certificate body";
        let signature: CertificateSignature = signer.try_sign(message).unwrap();
        let encoded = signature.to_bitstring().unwrap();
        let raw = ecdsa_signature_from_der(encoded.as_bytes().unwrap(), 32).unwrap();
        key.public_key()
            .verify_message(SignatureScheme::EcdsaP256Sha256, message, &raw)
            .unwrap();
    }
}
