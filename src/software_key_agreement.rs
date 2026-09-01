//! Protocol-neutral static software key agreement.
//!
//! This module owns raw ECDH, X25519, and X448 operations. Protocol layers retain
//! responsibility for algorithm identifiers, public-key containers, KDFs,
//! authorization policy, persistence, and error mapping.

use crate::software_signing::{EcKeyBackend, SoftwareSigningKey};
use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
};
use std::fmt;
use x448::{PublicKey as X448PublicKey, StaticSecret as X448SecretKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareKeyAgreementError {
    AlgorithmMismatch,
    InvalidPrivateKey,
    InvalidPublicKey,
    NonContributoryPublicKey,
    RandomnessUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MontgomeryCurve {
    X25519,
    X448,
}

#[derive(Clone)]
enum MontgomeryKeyBackend {
    Curve25519(X25519SecretKey),
    Curve448(X448SecretKey),
}

/// A persistent Montgomery-curve private key. Concrete crypto implementations
/// remain encapsulated so callers model the curve rather than a library type.
#[derive(Clone)]
pub struct SoftwareMontgomeryKey(MontgomeryKeyBackend);

// Both contained static-secret implementations clear their scalar on drop.
impl ZeroizeOnDrop for SoftwareMontgomeryKey {}

impl fmt::Debug for SoftwareMontgomeryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareMontgomeryKey")
            .field("curve", &self.curve())
            .finish_non_exhaustive()
    }
}

impl SoftwareMontgomeryKey {
    pub fn generate(curve: MontgomeryCurve) -> Result<Self, SoftwareKeyAgreementError> {
        match curve {
            MontgomeryCurve::X25519 => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                getrandom::fill(seed.as_mut())
                    .map_err(|_| SoftwareKeyAgreementError::RandomnessUnavailable)?;
                Ok(Self(MontgomeryKeyBackend::Curve25519(
                    X25519SecretKey::from(*seed),
                )))
            }
            MontgomeryCurve::X448 => {
                let mut seed = Zeroizing::new([0_u8; 56]);
                getrandom::fill(seed.as_mut())
                    .map_err(|_| SoftwareKeyAgreementError::RandomnessUnavailable)?;
                Ok(Self(MontgomeryKeyBackend::Curve448(X448SecretKey::from(
                    *seed,
                ))))
            }
        }
    }

    pub fn from_serialized(
        curve: MontgomeryCurve,
        serialized: &[u8],
    ) -> Result<Self, SoftwareKeyAgreementError> {
        match curve {
            MontgomeryCurve::X25519 => {
                let seed: [u8; 32] = serialized
                    .try_into()
                    .map_err(|_| SoftwareKeyAgreementError::InvalidPrivateKey)?;
                Ok(Self(MontgomeryKeyBackend::Curve25519(
                    X25519SecretKey::from(seed),
                )))
            }
            MontgomeryCurve::X448 => {
                let seed: [u8; 56] = serialized
                    .try_into()
                    .map_err(|_| SoftwareKeyAgreementError::InvalidPrivateKey)?;
                Ok(Self(MontgomeryKeyBackend::Curve448(X448SecretKey::from(
                    seed,
                ))))
            }
        }
    }

    pub const fn curve(&self) -> MontgomeryCurve {
        match &self.0 {
            MontgomeryKeyBackend::Curve25519(_) => MontgomeryCurve::X25519,
            MontgomeryKeyBackend::Curve448(_) => MontgomeryCurve::X448,
        }
    }

    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match &self.0 {
            MontgomeryKeyBackend::Curve25519(key) => key.to_bytes().to_vec(),
            MontgomeryKeyBackend::Curve448(key) => key.as_bytes().to_vec(),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        match &self.0 {
            MontgomeryKeyBackend::Curve25519(key) => X25519PublicKey::from(key).to_bytes().to_vec(),
            MontgomeryKeyBackend::Curve448(key) => X448PublicKey::from(key).as_bytes().to_vec(),
        }
    }

    pub fn derive(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
        match &self.0 {
            MontgomeryKeyBackend::Curve25519(key) => derive_x25519(key, peer_public_key),
            MontgomeryKeyBackend::Curve448(key) => derive_x448(key, peer_public_key),
        }
    }
}

/// Perform raw X25519 with an existing software private key.
pub fn derive_x25519(
    private_key: &X25519SecretKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
    let peer: [u8; 32] = peer_public_key
        .try_into()
        .map_err(|_| SoftwareKeyAgreementError::InvalidPublicKey)?;
    let shared = private_key.diffie_hellman(&X25519PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(SoftwareKeyAgreementError::NonContributoryPublicKey);
    }
    Ok(Zeroizing::new(shared.to_bytes().to_vec()))
}

/// Perform raw X448 with an existing software private key.
pub fn derive_x448(
    private_key: &X448SecretKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
    let peer = X448PublicKey::from_bytes(peer_public_key)
        .ok_or(SoftwareKeyAgreementError::InvalidPublicKey)?;
    let shared = private_key.diffie_hellman(&peer);
    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
}

/// Perform raw static ECDH for any RustCrypto short-Weierstrass curve.
///
/// The peer key may use any SEC1 encoding accepted by the curve. The returned
/// value is the fixed-width x-coordinate and is intentionally not passed
/// through a KDF.
pub fn derive_weierstrass<C>(
    private_key: &SecretKey<C>,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    let peer = PublicKey::<C>::from_sec1_bytes(peer_public_key)
        .map_err(|_| SoftwareKeyAgreementError::InvalidPublicKey)?;
    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        private_key.to_nonzero_scalar(),
        peer.as_affine(),
    );
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

/// Perform ECDH with any Weierstrass key owned by the shared software signing
/// key container.
pub fn derive_with_signing_key(
    private_key: &SoftwareSigningKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
    match private_key {
        SoftwareSigningKey::Ec(key) => match &key.0 {
            EcKeyBackend::P224(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::P256(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::P384(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::P521(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::Secp256k1(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::BrainpoolP256(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::BrainpoolP384(key) => derive_weierstrass(key, peer_public_key),
            EcKeyBackend::BrainpoolP512(key) => derive_weierstrass(key, peer_public_key),
        },
        SoftwareSigningKey::Edwards(_)
        | SoftwareSigningKey::Rsa(_)
        | SoftwareSigningKey::MlDsa(_) => Err(SoftwareKeyAgreementError::AlgorithmMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_signing::{SignatureScheme, SoftwarePublicKey};

    fn hex(encoded: &str) -> Vec<u8> {
        encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    b'A'..=b'F' => value - b'A' + 10,
                    _ => panic!("invalid test-vector hex"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn x448_matches_rfc_7748_known_answer() {
        let scalar = hex(concat!(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121",
            "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
        ));
        let peer = hex(concat!(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9",
            "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
        ));
        let expected = hex(concat!(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f",
            "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
        ));
        let key = SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X448, &scalar).unwrap();
        assert_eq!(key.derive(&peer).unwrap().as_slice(), expected);
    }

    #[test]
    fn every_shared_weierstrass_curve_agrees() {
        for algorithm in [
            SignatureScheme::EcdsaP224Sha224,
            SignatureScheme::EcdsaP256Sha256,
            SignatureScheme::EcdsaP384Sha384,
            SignatureScheme::EcdsaP521Sha512,
            SignatureScheme::EcdsaSecp256k1Sha256,
            SignatureScheme::EcdsaBrainpoolP256Sha256,
            SignatureScheme::EcdsaBrainpoolP384Sha384,
            SignatureScheme::EcdsaBrainpoolP512Sha512,
        ] {
            let first = SoftwareSigningKey::generate(algorithm).unwrap();
            let second = SoftwareSigningKey::generate(algorithm).unwrap();
            let SoftwarePublicKey::Ec {
                uncompressed: first_public,
                ..
            } = first.public_key()
            else {
                unreachable!();
            };
            let SoftwarePublicKey::Ec {
                uncompressed: second_public,
                ..
            } = second.public_key()
            else {
                unreachable!();
            };
            assert_eq!(
                derive_with_signing_key(&first, &second_public).unwrap(),
                derive_with_signing_key(&second, &first_public).unwrap()
            );
        }
    }

    #[test]
    fn montgomery_keys_round_trip_and_agree() {
        for curve in [MontgomeryCurve::X25519, MontgomeryCurve::X448] {
            let alice = SoftwareMontgomeryKey::generate(curve).unwrap();
            let serialized = alice.serialized();
            let restored = SoftwareMontgomeryKey::from_serialized(curve, &serialized).unwrap();
            assert_eq!(restored.public_key(), alice.public_key());

            let bob = SoftwareMontgomeryKey::generate(curve).unwrap();
            assert_eq!(
                restored.derive(&bob.public_key()).unwrap(),
                bob.derive(&alice.public_key()).unwrap()
            );
        }
    }

    #[test]
    fn montgomery_keys_reject_bad_and_noncontributory_peers() {
        let key = SoftwareMontgomeryKey::generate(MontgomeryCurve::X25519).unwrap();
        assert_eq!(
            key.derive(&[1; 31]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );
        assert_eq!(
            key.derive(&[0; 32]),
            Err(SoftwareKeyAgreementError::NonContributoryPublicKey)
        );

        let key = SoftwareMontgomeryKey::generate(MontgomeryCurve::X448).unwrap();
        assert_eq!(
            key.derive(&[1; 55]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );
        assert_eq!(
            key.derive(&[0; 56]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );
    }

    #[test]
    fn agreement_rejects_invalid_private_keys_peers_and_key_kinds() {
        assert!(matches!(
            SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X25519, &[0; 31]),
            Err(SoftwareKeyAgreementError::InvalidPrivateKey)
        ));
        assert!(matches!(
            SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X448, &[0; 55]),
            Err(SoftwareKeyAgreementError::InvalidPrivateKey)
        ));

        let p256 = SoftwareSigningKey::generate(SignatureScheme::EcdsaP256Sha256).unwrap();
        assert_eq!(
            derive_with_signing_key(&p256, &[4, 1, 2, 3]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );

        let ed25519 = SoftwareSigningKey::generate(SignatureScheme::Ed25519).unwrap();
        assert_eq!(
            derive_with_signing_key(&ed25519, &[0; 32]),
            Err(SoftwareKeyAgreementError::AlgorithmMismatch)
        );
    }
}
