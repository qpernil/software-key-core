//! Concrete protocol-neutral hybrid PQ/T key encapsulation mechanisms.
//!
//! This implements draft-irtf-cfrg-concrete-hybrid-kems-04. A decapsulation
//! key is the draft's single 32-byte seed; component keys are derived internally
//! and are never exposed as independently usable key objects.

use crate::post_quantum::{
    MlKemError, MlKemParameterSet, MlKemPrivateKey, ml_kem_encapsulate_deterministic,
};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha3::{
    Digest, Sha3_256, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{fmt, sync::Arc};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub const HYBRID_KEM_SECRET_LENGTH: usize = 32;
pub const HYBRID_KEM_SEED_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridKemConstruction {
    MlKem768P256,
    MlKem768X25519,
    MlKem1024P384,
}

impl HybridKemConstruction {
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1_249,
            Self::MlKem768X25519 => 1_216,
            Self::MlKem1024P384 => 1_665,
        }
    }

    pub const fn ciphertext_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1_153,
            Self::MlKem768X25519 => 1_120,
            Self::MlKem1024P384 => 1_665,
        }
    }

    pub const fn encapsulation_randomness_length(self) -> usize {
        32 + self.traditional_seed_length()
    }

    const fn ml_kem(self) -> MlKemParameterSet {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => MlKemParameterSet::MlKem768,
            Self::MlKem1024P384 => MlKemParameterSet::MlKem1024,
        }
    }

    const fn traditional_seed_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 128,
            Self::MlKem768X25519 => 32,
            Self::MlKem1024P384 => 48,
        }
    }

    const fn traditional_public_key_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 65,
            Self::MlKem768X25519 => 32,
            Self::MlKem1024P384 => 97,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::MlKem768P256 => b"MLKEM768-P256",
            Self::MlKem768X25519 => b"\\.//^\\",
            Self::MlKem1024P384 => b"MLKEM1024-P384",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridKemError {
    InvalidSeedLength,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidCiphertext,
    InvalidRandomnessLength,
    NonContributoryPublicKey,
    RandomnessUnavailable,
}

impl From<MlKemError> for HybridKemError {
    fn from(error: MlKemError) -> Self {
        match error {
            MlKemError::InvalidCiphertext => Self::InvalidCiphertext,
            MlKemError::InvalidPublicKey => Self::InvalidPublicKey,
            MlKemError::RandomnessUnavailable => Self::RandomnessUnavailable,
            _ => Self::InvalidPrivateKey,
        }
    }
}

#[derive(Clone)]
pub struct HybridKemPrivateKey {
    construction: HybridKemConstruction,
    seed: Arc<Zeroizing<[u8; HYBRID_KEM_SEED_LENGTH]>>,
}

impl ZeroizeOnDrop for HybridKemPrivateKey {}

impl fmt::Debug for HybridKemPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridKemPrivateKey")
            .field("construction", &self.construction)
            .finish_non_exhaustive()
    }
}

impl HybridKemPrivateKey {
    pub fn generate(construction: HybridKemConstruction) -> Result<Self, HybridKemError> {
        let mut seed = Zeroizing::new([0u8; HYBRID_KEM_SEED_LENGTH]);
        getrandom::fill(seed.as_mut()).map_err(|_| HybridKemError::RandomnessUnavailable)?;
        Ok(Self::from_seed(construction, *seed))
    }

    pub fn from_seed(construction: HybridKemConstruction, seed: [u8; 32]) -> Self {
        Self {
            construction,
            seed: Arc::new(Zeroizing::new(seed)),
        }
    }

    pub fn from_seed_slice(
        construction: HybridKemConstruction,
        seed: &[u8],
    ) -> Result<Self, HybridKemError> {
        Ok(Self::from_seed(
            construction,
            seed.try_into()
                .map_err(|_| HybridKemError::InvalidSeedLength)?,
        ))
    }

    pub const fn construction(&self) -> HybridKemConstruction {
        self.construction
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(**self.seed)
    }

    pub fn public_key(&self) -> Result<Vec<u8>, HybridKemError> {
        let components = expand_private(self.construction, &self.seed)?;
        let mut public = components.ml_kem.public_key();
        public.extend_from_slice(&components.traditional_public);
        debug_assert_eq!(public.len(), self.construction.public_key_length());
        Ok(public)
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, HybridKemError> {
        if ciphertext.len() != self.construction.ciphertext_length() {
            return Err(HybridKemError::InvalidCiphertext);
        }
        let components = expand_private(self.construction, &self.seed)?;
        let pq_length = self.construction.ml_kem().ciphertext_length();
        let (ciphertext_pq, ciphertext_t) = ciphertext.split_at(pq_length);
        let shared_pq = components.ml_kem.decapsulate(ciphertext_pq)?;
        let shared_t = components.traditional.derive(ciphertext_t)?;
        Ok(combine(
            self.construction,
            &shared_pq,
            &shared_t,
            ciphertext_t,
            &components.traditional_public,
        ))
    }
}

pub fn hybrid_kem_encapsulate(
    construction: HybridKemConstruction,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HybridKemError> {
    let mut randomness = Zeroizing::new(vec![0u8; construction.encapsulation_randomness_length()]);
    getrandom::fill(&mut randomness).map_err(|_| HybridKemError::RandomnessUnavailable)?;
    hybrid_kem_encapsulate_deterministic(construction, public_key, &randomness)
}

pub fn hybrid_kem_encapsulate_deterministic(
    construction: HybridKemConstruction,
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HybridKemError> {
    if public_key.len() != construction.public_key_length() {
        return Err(HybridKemError::InvalidPublicKey);
    }
    if randomness.len() != construction.encapsulation_randomness_length() {
        return Err(HybridKemError::InvalidRandomnessLength);
    }
    let pq_public_length = construction.ml_kem().public_key_length();
    let (public_pq, public_t) = public_key.split_at(pq_public_length);
    validate_traditional_public(construction, public_t)?;
    let (randomness_pq, randomness_t) = randomness.split_at(32);
    let randomness_pq: &[u8; 32] = randomness_pq
        .try_into()
        .map_err(|_| HybridKemError::InvalidRandomnessLength)?;
    let (ciphertext_pq, shared_pq) =
        ml_kem_encapsulate_deterministic(construction.ml_kem(), public_pq, randomness_pq)?;
    let ephemeral = TraditionalPrivate::from_seed(construction, randomness_t)?;
    let ciphertext_t = ephemeral.public_key();
    let shared_t = ephemeral.derive(public_t)?;
    let shared = combine(construction, &shared_pq, &shared_t, &ciphertext_t, public_t);
    let mut ciphertext = ciphertext_pq;
    ciphertext.extend_from_slice(&ciphertext_t);
    debug_assert_eq!(ciphertext.len(), construction.ciphertext_length());
    Ok((ciphertext, shared))
}

struct ExpandedPrivate {
    ml_kem: MlKemPrivateKey,
    traditional: TraditionalPrivate,
    traditional_public: Vec<u8>,
}

fn expand_private(
    construction: HybridKemConstruction,
    seed: &[u8; 32],
) -> Result<ExpandedPrivate, HybridKemError> {
    let output_length = 64 + construction.traditional_seed_length();
    let mut expanded = Zeroizing::new(vec![0u8; output_length]);
    let mut reader = Shake256::default().chain(seed).finalize_xof();
    reader.read(&mut expanded);
    let ml_seed: [u8; 64] = expanded[..64]
        .try_into()
        .map_err(|_| HybridKemError::InvalidPrivateKey)?;
    let traditional = TraditionalPrivate::from_seed(construction, &expanded[64..])?;
    let traditional_public = traditional.public_key();
    Ok(ExpandedPrivate {
        ml_kem: MlKemPrivateKey::from_seed(construction.ml_kem(), ml_seed),
        traditional,
        traditional_public,
    })
}

enum TraditionalPrivate {
    P256(p256::SecretKey),
    X25519(X25519SecretKey),
    P384(p384::SecretKey),
}

impl TraditionalPrivate {
    fn from_seed(construction: HybridKemConstruction, seed: &[u8]) -> Result<Self, HybridKemError> {
        if seed.len() != construction.traditional_seed_length() {
            return Err(HybridKemError::InvalidRandomnessLength);
        }
        match construction {
            HybridKemConstruction::MlKem768P256 => seed
                .as_chunks::<32>()
                .0
                .iter()
                .find_map(|candidate| p256::SecretKey::from_slice(candidate).ok())
                .map(Self::P256)
                .ok_or(HybridKemError::InvalidPrivateKey),
            HybridKemConstruction::MlKem768X25519 => {
                let seed: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| HybridKemError::InvalidPrivateKey)?;
                Ok(Self::X25519(X25519SecretKey::from(seed)))
            }
            HybridKemConstruction::MlKem1024P384 => p384::SecretKey::from_slice(seed)
                .map(Self::P384)
                .map_err(|_| HybridKemError::InvalidPrivateKey),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            Self::X25519(key) => X25519PublicKey::from(key).to_bytes().to_vec(),
            Self::P384(key) => key.public_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }

    fn derive(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, HybridKemError> {
        match self {
            Self::P256(key) => {
                let peer = p256::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| HybridKemError::InvalidPublicKey)?;
                Ok(Zeroizing::new(
                    p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                ))
            }
            Self::X25519(key) => {
                let peer: [u8; 32] = peer
                    .try_into()
                    .map_err(|_| HybridKemError::InvalidPublicKey)?;
                let shared = key.diffie_hellman(&X25519PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err(HybridKemError::NonContributoryPublicKey);
                }
                Ok(Zeroizing::new(shared.to_bytes().to_vec()))
            }
            Self::P384(key) => {
                let peer = p384::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| HybridKemError::InvalidPublicKey)?;
                Ok(Zeroizing::new(
                    p384::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                ))
            }
        }
    }
}

fn validate_traditional_public(
    construction: HybridKemConstruction,
    public: &[u8],
) -> Result<(), HybridKemError> {
    if public.len() != construction.traditional_public_key_length() {
        return Err(HybridKemError::InvalidPublicKey);
    }
    match construction {
        HybridKemConstruction::MlKem768P256 => p256::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| HybridKemError::InvalidPublicKey),
        HybridKemConstruction::MlKem768X25519 => {
            let public: [u8; 32] = public
                .try_into()
                .map_err(|_| HybridKemError::InvalidPublicKey)?;
            if public == [0u8; 32] {
                Err(HybridKemError::NonContributoryPublicKey)
            } else {
                Ok(())
            }
        }
        HybridKemConstruction::MlKem1024P384 => p384::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| HybridKemError::InvalidPublicKey),
    }
}

fn combine(
    construction: HybridKemConstruction,
    shared_pq: &[u8],
    shared_t: &[u8],
    ciphertext_t: &[u8],
    public_t: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut digest = Sha3_256::new();
    Digest::update(&mut digest, shared_pq);
    Digest::update(&mut digest, shared_t);
    Digest::update(&mut digest, ciphertext_t);
    Digest::update(&mut digest, public_t);
    Digest::update(&mut digest, construction.label());
    Zeroizing::new(digest.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

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
                    _ => panic!("invalid test-vector hex"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn draft_04_deterministic_vectors() {
        // First published vector for each construction. The seed is 32 zero
        // bytes and the deterministic-encapsulation randomness is 0x64 repeated
        // to the construction's required length. SHA-256 compacts the large
        // public-key and ciphertext assertions without weakening the KAT.
        for (construction, public_hash, ciphertext_hash, shared_secret) in [
            (
                HybridKemConstruction::MlKem768P256,
                "2627712d7aa5b010d292dfaef982ff9dd66ccdadb35804780b9d891c7fe29526",
                "5e695b18578462c0d8ab9bbefbe733040379dc08598f17fc2a7627fdeb9d2c42",
                "9bd018e869bb01b63fb8f5da374a73d347ea14cb2bc570b13d0908e2288ec456",
            ),
            (
                HybridKemConstruction::MlKem768X25519,
                "3bb0b003f553f49f38bab31546b7f4fdd323c74cbf4aaf97d9703ede4e83eff7",
                "89ef4ccf41483c6fa62744d23a0fd6072a2e637f74564db7f618d1516ed8a6cd",
                "e5ba94031ea6efd69c09c254f6d9783136ba6037e2d4c43bcccf19d6f3f4343a",
            ),
            (
                HybridKemConstruction::MlKem1024P384,
                "9275d0f9dfe19bd24a15364a9e010baf1ec4b78211c03263c3d6a94025de98f8",
                "05ec1e48c1dc04c88929fbf38892f556c3ce729fd86af361dc5d4aff555dc59c",
                "8c028c6ea72a1c59408e2b15dd8fed8008517e861cd2329b159bda1919ea656c",
            ),
        ] {
            let private = HybridKemPrivateKey::from_seed(construction, [0u8; 32]);
            let public = private.public_key().unwrap();
            assert_eq!(Sha256::digest(&public).as_slice(), hex(public_hash));
            let randomness = vec![0x64; construction.encapsulation_randomness_length()];
            let (ciphertext, shared) =
                hybrid_kem_encapsulate_deterministic(construction, &public, &randomness).unwrap();
            assert_eq!(Sha256::digest(&ciphertext).as_slice(), hex(ciphertext_hash));
            assert_eq!(shared.as_slice(), hex(shared_secret));
            assert_eq!(
                private.decapsulate(&ciphertext).unwrap().as_slice(),
                shared.as_slice()
            );
        }
    }

    #[test]
    fn all_constructions_round_trip_and_reject_cross_use() {
        let constructions = [
            HybridKemConstruction::MlKem768P256,
            HybridKemConstruction::MlKem768X25519,
            HybridKemConstruction::MlKem1024P384,
        ];
        for construction in constructions {
            let private = HybridKemPrivateKey::generate(construction).unwrap();
            let public = private.public_key().unwrap();
            let (ciphertext, shared) = hybrid_kem_encapsulate(construction, &public).unwrap();
            assert_eq!(
                private.decapsulate(&ciphertext).unwrap().as_slice(),
                shared.as_slice()
            );
            assert_eq!(shared.len(), HYBRID_KEM_SECRET_LENGTH);

            for other in constructions {
                if other != construction {
                    assert!(hybrid_kem_encapsulate(other, &public).is_err());
                    assert!(
                        HybridKemPrivateKey::from_seed(other, *private.seed())
                            .decapsulate(&ciphertext)
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn malformed_traditional_values_are_rejected() {
        for construction in [
            HybridKemConstruction::MlKem768P256,
            HybridKemConstruction::MlKem768X25519,
            HybridKemConstruction::MlKem1024P384,
        ] {
            let private = HybridKemPrivateKey::from_seed(construction, [7u8; 32]);
            let mut public = private.public_key().unwrap();
            let start = construction.ml_kem().public_key_length();
            public[start..].fill(0);
            assert!(hybrid_kem_encapsulate(construction, &public).is_err());
        }
    }
}
