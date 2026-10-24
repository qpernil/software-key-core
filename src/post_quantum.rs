//! Role-neutral post-quantum key operations shared by virtual applets.
//!
//! Protocol-specific identifiers, encodings, policy, and error mapping belong
//! in their callers. This module deliberately operates on raw FIPS 204 keys,
//! messages, contexts, and signatures so it can also be reused by `pkcs11rs`.

use ::ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa44, MlDsa65, MlDsa87,
    MlDsaParams, Seed, Signature, SigningKey, VerifyingKey,
};
use std::{fmt, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParameterSet {
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1_184,
            Self::MlKem1024 => 1_568,
        }
    }

    pub const fn expanded_private_key_length(self) -> usize {
        match self {
            Self::MlKem512 => 1_632,
            Self::MlKem768 => 2_400,
            Self::MlKem1024 => 3_168,
        }
    }

    pub const fn ciphertext_length(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1_088,
            Self::MlKem1024 => 1_568,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemError {
    InvalidSeedLength,
    InvalidExpandedPrivateKey,
    InvalidPublicKey,
    InvalidCiphertext,
    InvalidPrivateKey,
    RandomnessUnavailable,
    EncodingFailed,
}

/// An ML-KEM private key with immutable expanded state shared between handles.
#[derive(Clone)]
pub enum MlKemPrivateKey {
    MlKem512(Arc<::ml_kem::DecapsulationKey<::ml_kem::MlKem512>>),
    MlKem768(Arc<::ml_kem::DecapsulationKey<::ml_kem::MlKem768>>),
    MlKem1024(Arc<::ml_kem::DecapsulationKey<::ml_kem::MlKem1024>>),
}

// The `ml-kem` dependency zeroizes the expanded key when its last owner drops.
impl ZeroizeOnDrop for MlKemPrivateKey {}

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemPrivateKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}

impl MlKemPrivateKey {
    /// Raw seed, expanded key, or seed followed by expanded key. Exact,
    /// parameter-set-specific lengths distinguish the three representations.
    pub fn from_serialized(
        parameter_set: MlKemParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlKemError> {
        if encoded.len() == 64 {
            Self::from_components(parameter_set, Some(encoded), None)
        } else if encoded.len() == 64 + parameter_set.expanded_private_key_length() {
            let (seed, expanded) = encoded.split_at(64);
            Self::from_components(parameter_set, Some(seed), Some(expanded))
        } else {
            Self::from_components(parameter_set, None, Some(encoded))
        }
    }

    /// Import raw FIPS private components with one shared consistency policy.
    pub fn from_components(
        parameter_set: MlKemParameterSet,
        seed: Option<&[u8]>,
        expanded: Option<&[u8]>,
    ) -> Result<Self, MlKemError> {
        match (seed, expanded) {
            (Some(seed), Some(expanded)) => {
                Self::from_seed_and_expanded(parameter_set, seed, expanded)
            }
            (Some(seed), None) => Self::from_seed_slice(parameter_set, seed),
            (None, Some(expanded)) => Self::from_expanded_private_key(parameter_set, expanded),
            (None, None) => Err(MlKemError::InvalidPrivateKey),
        }
    }

    /// Canonical raw storage: retain the seed when known, otherwise the
    /// expanded private encoding. Never synthesize a seed for an imported key.
    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        self.seed()
            .map(|seed| Zeroizing::new(seed.to_vec()))
            .unwrap_or_else(|| self.expanded_private_key())
    }

    pub fn generate(parameter_set: MlKemParameterSet) -> Result<Self, MlKemError> {
        let mut seed = Zeroizing::new([0u8; 64]);
        getrandom::fill(seed.as_mut()).map_err(|_| MlKemError::RandomnessUnavailable)?;
        Ok(Self::from_seed(parameter_set, *seed))
    }

    pub fn from_seed(parameter_set: MlKemParameterSet, seed: [u8; 64]) -> Self {
        let seed = ::ml_kem::Seed::from(seed);
        match parameter_set {
            MlKemParameterSet::MlKem512 => {
                Self::MlKem512(Arc::new(::ml_kem::DecapsulationKey::from_seed(seed)))
            }
            MlKemParameterSet::MlKem768 => {
                Self::MlKem768(Arc::new(::ml_kem::DecapsulationKey::from_seed(seed)))
            }
            MlKemParameterSet::MlKem1024 => {
                Self::MlKem1024(Arc::new(::ml_kem::DecapsulationKey::from_seed(seed)))
            }
        }
    }

    pub fn from_seed_slice(
        parameter_set: MlKemParameterSet,
        seed: &[u8],
    ) -> Result<Self, MlKemError> {
        Ok(Self::from_seed(
            parameter_set,
            seed.try_into().map_err(|_| MlKemError::InvalidSeedLength)?,
        ))
    }

    /// Import an expanded key after encoding/hash checks and a randomized
    /// encapsulation/decapsulation pairwise consistency check (FIPS 203 §7.1).
    pub fn from_expanded_private_key(
        parameter_set: MlKemParameterSet,
        expanded: &[u8],
    ) -> Result<Self, MlKemError> {
        Self::from_expanded_private_key_with_randomness(parameter_set, expanded, |randomness| {
            getrandom::fill(randomness).map_err(|_| MlKemError::RandomnessUnavailable)
        })
    }

    #[allow(deprecated)]
    fn from_expanded_private_key_with_randomness(
        parameter_set: MlKemParameterSet,
        expanded: &[u8],
        fill_randomness: impl FnOnce(&mut [u8; 32]) -> Result<(), MlKemError>,
    ) -> Result<Self, MlKemError> {
        macro_rules! decode {
            ($params:ty, $variant:ident) => {{
                let expanded = ::ml_kem::ExpandedDecapsulationKey::<$params>::try_from(expanded)
                    .map_err(|_| MlKemError::InvalidExpandedPrivateKey)?;
                ::ml_kem::ExpandedKeyEncoding::from_expanded_bytes(&expanded)
                    .map(|key| Self::$variant(Arc::new(key)))
                    .map_err(|_| MlKemError::InvalidExpandedPrivateKey)
            }};
        }
        let key = match parameter_set {
            MlKemParameterSet::MlKem512 => decode!(::ml_kem::MlKem512, MlKem512),
            MlKemParameterSet::MlKem768 => decode!(::ml_kem::MlKem768, MlKem768),
            MlKemParameterSet::MlKem1024 => decode!(::ml_kem::MlKem1024, MlKem1024),
        }?;
        // FIPS 203 §7.1 key-pair check, step 4. Decapsulation uses implicit
        // rejection, so successful decoding/decapsulation alone cannot establish
        // consistency. Compare the shared secrets, in constant time.
        let mut randomness = Zeroizing::new([0u8; 32]);
        fill_randomness(&mut randomness)?;
        let (ciphertext, expected) =
            ml_kem_encapsulate_deterministic(parameter_set, &key.public_key(), &randomness)?;
        let actual = key.decapsulate(&ciphertext)?;
        if !bool::from(expected.as_slice().ct_eq(actual.as_slice())) {
            return Err(MlKemError::InvalidExpandedPrivateKey);
        }
        Ok(key)
    }

    fn algorithm_for(
        parameter_set: MlKemParameterSet,
    ) -> ::ml_dsa::pkcs8::AlgorithmIdentifierRef<'static> {
        use ::ml_kem::pkcs8::AssociatedAlgorithmIdentifier;
        match parameter_set {
            MlKemParameterSet::MlKem512 => ::ml_kem::MlKem512::ALGORITHM_IDENTIFIER,
            MlKemParameterSet::MlKem768 => ::ml_kem::MlKem768::ALGORITHM_IDENTIFIER,
            MlKemParameterSet::MlKem1024 => ::ml_kem::MlKem1024::ALGORITHM_IDENTIFIER,
        }
    }

    pub fn from_seed_and_expanded(
        parameter_set: MlKemParameterSet,
        seed: &[u8],
        expanded: &[u8],
    ) -> Result<Self, MlKemError> {
        let key = Self::from_seed_slice(parameter_set, seed)?;
        if !bool::from(key.expanded_private_key().as_slice().ct_eq(expanded)) {
            return Err(MlKemError::InvalidExpandedPrivateKey);
        }
        Ok(key)
    }

    pub fn from_pkcs8_der(
        parameter_set: MlKemParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlKemError> {
        use crate::pqc_key_encoding::{self, PrivateEncoding};
        let decoded = pqc_key_encoding::decode(encoded, Self::algorithm_for(parameter_set))
            .map_err(|_| MlKemError::InvalidPrivateKey)?;
        let key = match decoded.encoding {
            PrivateEncoding::Seed(seed) => Self::from_seed_slice(parameter_set, seed)?,
            PrivateEncoding::Expanded(expanded) => {
                Self::from_expanded_private_key(parameter_set, expanded)?
            }
            PrivateEncoding::Both { seed, expanded } => {
                Self::from_seed_and_expanded(parameter_set, seed, expanded)?
            }
        };
        if decoded
            .public
            .is_some_and(|public| key.public_key() != public)
        {
            return Err(MlKemError::InvalidPrivateKey);
        }
        Ok(key)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, MlKemError> {
        use crate::pqc_key_encoding::{self, PrivateEncoding};
        let algorithm = Self::algorithm_for(self.parameter_set());
        match self.seed() {
            Some(seed) => pqc_key_encoding::encode(algorithm, PrivateEncoding::Seed(&seed), None),
            None => pqc_key_encoding::encode(
                algorithm,
                PrivateEncoding::Expanded(&self.expanded_private_key()),
                None,
            ),
        }
        .map_err(|_| MlKemError::EncodingFailed)
    }

    pub const fn parameter_set(&self) -> MlKemParameterSet {
        match self {
            Self::MlKem512(_) => MlKemParameterSet::MlKem512,
            Self::MlKem768(_) => MlKemParameterSet::MlKem768,
            Self::MlKem1024(_) => MlKemParameterSet::MlKem1024,
        }
    }

    pub fn seed(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::MlKem512(key) => key.to_seed(),
            Self::MlKem768(key) => key.to_seed(),
            Self::MlKem1024(key) => key.to_seed(),
        }
        .map(|seed| Zeroizing::new(seed.to_vec()))
    }

    #[allow(deprecated)]
    pub fn expanded_private_key(&self) -> Zeroizing<Vec<u8>> {
        use ::ml_kem::ExpandedKeyEncoding;
        Zeroizing::new(match self {
            Self::MlKem512(key) => key.to_expanded_bytes().to_vec(),
            Self::MlKem768(key) => key.to_expanded_bytes().to_vec(),
            Self::MlKem1024(key) => key.to_expanded_bytes().to_vec(),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        use ::ml_kem::kem::KeyExport;
        match self {
            Self::MlKem512(key) => key.encapsulation_key().to_bytes().to_vec(),
            Self::MlKem768(key) => key.encapsulation_key().to_bytes().to_vec(),
            Self::MlKem1024(key) => key.encapsulation_key().to_bytes().to_vec(),
        }
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, MlKemError> {
        use ::ml_kem::kem::Decapsulate;
        macro_rules! decapsulate {
            ($key:expr, $params:ty) => {{
                let ciphertext = ::ml_kem::kem::Ciphertext::<$params>::try_from(ciphertext)
                    .map_err(|_| MlKemError::InvalidCiphertext)?;
                Ok(Zeroizing::new($key.decapsulate(&ciphertext).to_vec()))
            }};
        }
        match self {
            Self::MlKem512(key) => decapsulate!(key, ::ml_kem::MlKem512),
            Self::MlKem768(key) => decapsulate!(key, ::ml_kem::MlKem768),
            Self::MlKem1024(key) => decapsulate!(key, ::ml_kem::MlKem1024),
        }
    }
}

pub fn ml_kem_encapsulate(
    parameter_set: MlKemParameterSet,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), MlKemError> {
    let mut randomness = Zeroizing::new([0u8; 32]);
    getrandom::fill(randomness.as_mut()).map_err(|_| MlKemError::RandomnessUnavailable)?;
    ml_kem_encapsulate_deterministic(parameter_set, public_key, &randomness)
}

/// Deterministic FIPS 203 encapsulation used by composite KEM constructions
/// and known-answer tests. Protocol callers should normally use
/// [`ml_kem_encapsulate`].
pub fn ml_kem_encapsulate_deterministic(
    parameter_set: MlKemParameterSet,
    public_key: &[u8],
    randomness: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), MlKemError> {
    macro_rules! encapsulate {
        ($params:ty) => {{
            let encoded =
                ::ml_kem::kem::Key::<::ml_kem::EncapsulationKey<$params>>::try_from(public_key)
                    .map_err(|_| MlKemError::InvalidPublicKey)?;
            let key = ::ml_kem::EncapsulationKey::<$params>::new(&encoded)
                .map_err(|_| MlKemError::InvalidPublicKey)?;
            let (ciphertext, shared) =
                key.encapsulate_deterministic(&::ml_kem::B32::from(*randomness));
            Ok((ciphertext.to_vec(), Zeroizing::new(shared.to_vec())))
        }};
    }
    match parameter_set {
        MlKemParameterSet::MlKem512 => encapsulate!(::ml_kem::MlKem512),
        MlKemParameterSet::MlKem768 => encapsulate!(::ml_kem::MlKem768),
        MlKemParameterSet::MlKem1024 => encapsulate!(::ml_kem::MlKem1024),
    }
}

pub fn ml_kem_public_key_info(
    parameter_set: MlKemParameterSet,
    public_key: &[u8],
) -> Result<Vec<u8>, MlKemError> {
    macro_rules! encode {
        ($params:ty) => {{
            use ::ml_kem::pkcs8::EncodePublicKey;
            let encoded =
                ::ml_kem::kem::Key::<::ml_kem::EncapsulationKey<$params>>::try_from(public_key)
                    .map_err(|_| MlKemError::InvalidPublicKey)?;
            ::ml_kem::EncapsulationKey::<$params>::new(&encoded)
                .map_err(|_| MlKemError::InvalidPublicKey)?
                .to_public_key_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|_| MlKemError::EncodingFailed)
        }};
    }
    match parameter_set {
        MlKemParameterSet::MlKem512 => encode!(::ml_kem::MlKem512),
        MlKemParameterSet::MlKem768 => encode!(::ml_kem::MlKem768),
        MlKemParameterSet::MlKem1024 => encode!(::ml_kem::MlKem1024),
    }
}

/// One of the three FIPS 204 ML-DSA parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    pub const fn expanded_private_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2_560,
            Self::MlDsa65 => 4_032,
            Self::MlDsa87 => 4_896,
        }
    }

    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 1_312,
            Self::MlDsa65 => 1_952,
            Self::MlDsa87 => 2_592,
        }
    }

    pub const fn signature_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2_420,
            Self::MlDsa65 => 3_309,
            Self::MlDsa87 => 4_627,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaError {
    InvalidSeedLength,
    InvalidExpandedPrivateKey,
    InvalidPrivateKey,
    InvalidContext,
    InvalidPublicKey,
    InvalidSignature,
    RandomnessUnavailable,
    SigningFailed,
}

/// How an ML-DSA signature obtains its per-signature randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaRandomization {
    /// Use the deterministic FIPS 204 variant.
    Deterministic,
    /// Require fresh operating-system randomness and fail if it is unavailable.
    Randomized,
    /// Prefer fresh randomness but fall back to the permitted deterministic variant.
    HedgePreferred,
}

enum MlDsaKeyMaterial<P: MlDsaParams> {
    Seeded(Box<SigningKey<P>>),
    Expanded {
        key: Box<ExpandedSigningKey<P>>,
        public: Box<VerifyingKey<P>>,
    },
}

/// Validated ML-DSA material. Its private fields keep unchecked expanded keys
/// out of the shared operation API; the outer handle shares it through Arc.
pub struct MlDsaKey<P: MlDsaParams>(MlDsaKeyMaterial<P>);

impl<P: MlDsaParams> MlDsaKey<P> {
    fn from_seed(seed: &Seed) -> Self {
        Self(MlDsaKeyMaterial::Seeded(Box::new(SigningKey::from_seed(
            seed,
        ))))
    }

    fn from_expanded(encoded: &[u8]) -> Result<Self, MlDsaError> {
        use signature::Verifier;
        let key = decode_expanded_ml_dsa::<P>(encoded)?;
        let public = Box::new(key.verifying_key());
        // Operational pairwise test, after algebraic validation has made the
        // untrusted components safe to use in signing (FIPS 204 Algorithms 6–8).
        let message = b"software-key-core ML-DSA expanded-import pairwise test";
        let signature = key
            .sign_deterministic(message, b"")
            .map_err(|_| MlDsaError::InvalidExpandedPrivateKey)?;
        public
            .verify(message, &signature)
            .map_err(|_| MlDsaError::InvalidExpandedPrivateKey)?;
        Ok(Self(MlDsaKeyMaterial::Expanded { key, public }))
    }

    fn expanded_key(&self) -> &ExpandedSigningKey<P> {
        match &self.0 {
            MlDsaKeyMaterial::Seeded(key) => key.expanded_key(),
            MlDsaKeyMaterial::Expanded { key, .. } => key,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match &self.0 {
            MlDsaKeyMaterial::Seeded(key) => key.as_ref().as_ref().encode().to_vec(),
            MlDsaKeyMaterial::Expanded { public, .. } => public.encode().to_vec(),
        }
    }

    fn seed(&self) -> Option<Zeroizing<[u8; 32]>> {
        match &self.0 {
            MlDsaKeyMaterial::Seeded(key) => Some(Zeroizing::new((*key.as_seed()).into())),
            MlDsaKeyMaterial::Expanded { .. } => None,
        }
    }
}

// Keep the large by-value dependency return out of the operation/PCT frame.
#[inline(never)]
fn decode_expanded_ml_dsa<P: MlDsaParams>(
    encoded: &[u8],
) -> Result<Box<ExpandedSigningKey<P>>, MlDsaError> {
    let encoded = ExpandedSigningKeyBytes::<P>::try_from(encoded)
        .map_err(|_| MlDsaError::InvalidExpandedPrivateKey)?;
    match ExpandedSigningKey::<P>::from_expanded_checked(&encoded) {
        Ok(key) => Ok(Box::new(key)),
        Err(_) => Err(MlDsaError::InvalidExpandedPrivateKey),
    }
}

/// An ML-DSA private key with immutable expanded state shared between handles.
#[derive(Clone)]
pub enum MlDsaPrivateKey {
    MlDsa44(Arc<MlDsaKey<MlDsa44>>),
    MlDsa65(Arc<MlDsaKey<MlDsa65>>),
    MlDsa87(Arc<MlDsaKey<MlDsa87>>),
}

// The `ml-dsa` dependency zeroizes the expanded key when its last owner drops.
impl ZeroizeOnDrop for MlDsaPrivateKey {}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaPrivateKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}

impl MlDsaPrivateKey {
    /// Import raw FIPS private components with one shared consistency policy.
    pub fn from_components(
        parameter_set: MlDsaParameterSet,
        seed: Option<&[u8]>,
        expanded: Option<&[u8]>,
    ) -> Result<Self, MlDsaError> {
        match (seed, expanded) {
            (Some(seed), Some(expanded)) => {
                Self::from_seed_and_expanded(parameter_set, seed, expanded)
            }
            (Some(seed), None) => Self::from_seed_slice(parameter_set, seed),
            (None, Some(expanded)) => Self::from_expanded_private_key(parameter_set, expanded),
            (None, None) => Err(MlDsaError::InvalidPrivateKey),
        }
    }

    /// Canonical raw storage: retain the seed when known, otherwise the
    /// expanded private encoding. Never synthesize a seed for an imported key.
    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        self.seed()
            .map(|seed| Zeroizing::new(seed.to_vec()))
            .unwrap_or_else(|| self.expanded_private_key())
    }

    fn algorithm(&self) -> ::ml_dsa::pkcs8::AlgorithmIdentifierRef<'static> {
        Self::algorithm_for(self.parameter_set())
    }

    fn algorithm_for(
        parameter_set: MlDsaParameterSet,
    ) -> ::ml_dsa::pkcs8::AlgorithmIdentifierRef<'static> {
        use ::ml_dsa::pkcs8::spki::AssociatedAlgorithmIdentifier;
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => MlDsa44::ALGORITHM_IDENTIFIER,
            MlDsaParameterSet::MlDsa65 => MlDsa65::ALGORITHM_IDENTIFIER,
            MlDsaParameterSet::MlDsa87 => MlDsa87::ALGORITHM_IDENTIFIER,
        }
    }

    pub fn from_pkcs8_der(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        use crate::pqc_key_encoding::{self, PrivateEncoding};
        let decoded = pqc_key_encoding::decode(encoded, Self::algorithm_for(parameter_set))
            .map_err(|_| MlDsaError::InvalidPrivateKey)?;
        let key = match decoded.encoding {
            PrivateEncoding::Seed(seed) => Self::from_seed_slice(parameter_set, seed)?,
            PrivateEncoding::Expanded(expanded) => {
                Self::from_expanded_private_key(parameter_set, expanded)?
            }
            PrivateEncoding::Both { seed, expanded } => {
                Self::from_seed_and_expanded(parameter_set, seed, expanded)?
            }
        };
        if decoded
            .public
            .is_some_and(|public| key.public_key() != public)
        {
            return Err(MlDsaError::InvalidPrivateKey);
        }
        Ok(key)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, MlDsaError> {
        use crate::pqc_key_encoding::{self, PrivateEncoding};
        match self.seed() {
            Some(seed) => pqc_key_encoding::encode(
                self.algorithm(),
                PrivateEncoding::Seed(seed.as_ref()),
                None,
            ),
            None => pqc_key_encoding::encode(
                self.algorithm(),
                PrivateEncoding::Expanded(&self.expanded_private_key()),
                None,
            ),
        }
        .map_err(|_| MlDsaError::InvalidPrivateKey)
    }

    /// When both representations are supplied, require an exact seed expansion match.
    pub fn from_seed_and_expanded(
        parameter_set: MlDsaParameterSet,
        seed: &[u8],
        expanded: &[u8],
    ) -> Result<Self, MlDsaError> {
        let key = Self::from_seed_slice(parameter_set, seed)?;
        if !bool::from(key.expanded_private_key().as_slice().ct_eq(expanded)) {
            return Err(MlDsaError::InvalidExpandedPrivateKey);
        }
        Ok(key)
    }

    pub fn from_expanded_private_key(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        Ok(match parameter_set {
            MlDsaParameterSet::MlDsa44 => {
                Self::MlDsa44(Arc::new(MlDsaKey::from_expanded(encoded)?))
            }
            MlDsaParameterSet::MlDsa65 => {
                Self::MlDsa65(Arc::new(MlDsaKey::from_expanded(encoded)?))
            }
            MlDsaParameterSet::MlDsa87 => {
                Self::MlDsa87(Arc::new(MlDsaKey::from_expanded(encoded)?))
            }
        })
    }

    /// Raw seed, expanded key, or seed followed by expanded key. Exact,
    /// parameter-set-specific lengths distinguish the three representations.
    pub fn from_serialized(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        if encoded.len() == 32 {
            Self::from_components(parameter_set, Some(encoded), None)
        } else if encoded.len() == 32 + parameter_set.expanded_private_key_length() {
            let (seed, expanded) = encoded.split_at(32);
            Self::from_components(parameter_set, Some(seed), Some(expanded))
        } else {
            Self::from_components(parameter_set, None, Some(encoded))
        }
    }

    pub fn generate(parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| MlDsaError::RandomnessUnavailable)?;
        Self::from_seed_slice(parameter_set, seed.as_ref())
    }

    /// Construct a key from its seed.
    pub fn from_seed(parameter_set: MlDsaParameterSet, seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        Self::from_seed_slice(parameter_set, seed.as_ref()).expect("fixed-size ML-DSA seed")
    }

    pub fn from_seed_slice(
        parameter_set: MlDsaParameterSet,
        seed: &[u8],
    ) -> Result<Self, MlDsaError> {
        let seed = Zeroizing::new(Seed::try_from(seed).map_err(|_| MlDsaError::InvalidSeedLength)?);
        Ok(match parameter_set {
            MlDsaParameterSet::MlDsa44 => Self::MlDsa44(Arc::new(MlDsaKey::from_seed(&seed))),
            MlDsaParameterSet::MlDsa65 => Self::MlDsa65(Arc::new(MlDsaKey::from_seed(&seed))),
            MlDsaParameterSet::MlDsa87 => Self::MlDsa87(Arc::new(MlDsaKey::from_seed(&seed))),
        })
    }

    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        match self {
            Self::MlDsa44(_) => MlDsaParameterSet::MlDsa44,
            Self::MlDsa65(_) => MlDsaParameterSet::MlDsa65,
            Self::MlDsa87(_) => MlDsaParameterSet::MlDsa87,
        }
    }

    pub fn seed(&self) -> Option<Zeroizing<[u8; 32]>> {
        match self {
            Self::MlDsa44(key) => key.seed(),
            Self::MlDsa65(key) => key.seed(),
            Self::MlDsa87(key) => key.seed(),
        }
    }

    /// Expanded FIPS 204 private-key encoding used by PKCS #11 `CKA_VALUE`.
    #[allow(deprecated)]
    pub fn expanded_private_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            Self::MlDsa44(key) => key.expanded_key().to_expanded().to_vec(),
            Self::MlDsa65(key) => key.expanded_key().to_expanded().to_vec(),
            Self::MlDsa87(key) => key.expanded_key().to_expanded().to_vec(),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        // Borrow the cached verification key: Keypair::verifying_key would
        // clone its expanded matrix merely to encode the public bytes.
        match self {
            Self::MlDsa44(key) => key.public_key(),
            Self::MlDsa65(key) => key.public_key(),
            Self::MlDsa87(key) => key.public_key(),
        }
    }

    pub fn sign(
        &self,
        message: &[u8],
        context: &[u8],
        randomization: MlDsaRandomization,
    ) -> Result<Vec<u8>, MlDsaError> {
        if context.len() > 255 {
            return Err(MlDsaError::InvalidContext);
        }
        macro_rules! sign {
            ($key:expr) => {{
                let expanded = $key.expanded_key();
                let signature = match randomization {
                    MlDsaRandomization::Deterministic => expanded
                        .sign_deterministic(message, context)
                        .map_err(|_| MlDsaError::SigningFailed)?,
                    MlDsaRandomization::Randomized => expanded
                        .sign_randomized(message, context, &mut getrandom::SysRng)
                        .map_err(|_| MlDsaError::RandomnessUnavailable)?,
                    MlDsaRandomization::HedgePreferred => expanded
                        .sign_randomized(message, context, &mut getrandom::SysRng)
                        .or_else(|_| expanded.sign_deterministic(message, context))
                        .map_err(|_| MlDsaError::SigningFailed)?,
                };
                Ok(signature.encode().to_vec())
            }};
        }
        match self {
            Self::MlDsa44(key) => sign!(key),
            Self::MlDsa65(key) => sign!(key),
            Self::MlDsa87(key) => sign!(key),
        }
    }

    /// Sign an already hashed message using FIPS 204 HashML-DSA.
    pub fn sign_prehash(
        &self,
        digest: &[u8],
        context: &[u8],
        hash: MlDsaPrehash,
        randomization: MlDsaRandomization,
    ) -> Result<Vec<u8>, MlDsaError> {
        let message = hash.encode(digest, context)?;
        let mut randomizer = Zeroizing::new([0u8; 32]);
        if randomization != MlDsaRandomization::Deterministic
            && getrandom::fill(randomizer.as_mut()).is_err()
        {
            if randomization == MlDsaRandomization::Randomized {
                return Err(MlDsaError::RandomnessUnavailable);
            }
            // A failed RNG may have partially filled the buffer.
            *randomizer = [0; 32];
        }
        let rnd = (*randomizer).into();
        macro_rules! sign {
            ($key:expr) => {
                Ok($key
                    .expanded_key()
                    .sign_internal(&[&message], &rnd)
                    .encode()
                    .to_vec())
            };
        }
        match self {
            Self::MlDsa44(key) => sign!(key),
            Self::MlDsa65(key) => sign!(key),
            Self::MlDsa87(key) => sign!(key),
        }
    }

    /// Produce a randomized FIPS 204 signature, falling back to the permitted
    /// deterministic variant if the operating-system RNG is unavailable.
    pub fn sign_hedged(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, MlDsaError> {
        self.sign(message, context, MlDsaRandomization::HedgePreferred)
    }

    pub fn sign_deterministic(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, MlDsaError> {
        self.sign(message, context, MlDsaRandomization::Deterministic)
    }
}

/// FIPS 204 prehash identifiers: the final arc of the NIST hash OID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsaPrehash(u8);

impl MlDsaPrehash {
    pub fn from_id(id: u8) -> Option<Self> {
        matches!(id, 1..=4 | 7..=12).then_some(Self(id))
    }
    pub const fn id(self) -> u8 {
        self.0
    }
    pub const fn digest_length(self) -> usize {
        match self.0 {
            4 | 7 => 28,
            1 | 8 | 11 => 32,
            2 | 9 => 48,
            _ => 64,
        }
    }
    /// Incremental prehash state for caller-side message hashing.
    pub fn context(self) -> MlDsaPrehashContext {
        use crate::digest::{HashAlgorithm, HashContext};
        let state = match self.0 {
            11 => MlDsaPrehashState::Shake128(sha3::Shake128::default()),
            12 => MlDsaPrehashState::Shake256(sha3::Shake256::default()),
            id => {
                let algorithm = match id {
                    1 => HashAlgorithm::Sha256,
                    2 => HashAlgorithm::Sha384,
                    3 => HashAlgorithm::Sha512,
                    4 => HashAlgorithm::Sha224,
                    7 => HashAlgorithm::Sha3_224,
                    8 => HashAlgorithm::Sha3_256,
                    9 => HashAlgorithm::Sha3_384,
                    _ => HashAlgorithm::Sha3_512,
                };
                MlDsaPrehashState::Hash(HashContext::new(algorithm))
            }
        };
        MlDsaPrehashContext { hash: self, state }
    }

    /// Compute the FIPS 204 prehash outside the signing device.
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        let mut context = self.context();
        context.update(message);
        context.finalize()
    }

    /// HashML-DSA's domain-separated input to ML-DSA.Sign_internal.
    pub fn encode(self, digest: &[u8], context: &[u8]) -> Result<Vec<u8>, MlDsaError> {
        if context.len() > 255 {
            return Err(MlDsaError::InvalidContext);
        }
        if digest.len() != self.digest_length() {
            return Err(MlDsaError::InvalidSignature);
        }
        let mut message = vec![1, context.len() as u8];
        message.extend_from_slice(context);
        message.extend_from_slice(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, self.0,
        ]);
        message.extend_from_slice(digest);
        Ok(message)
    }
}

/// Fixed-size, cloneable state for HashML-DSA prehashing.
#[derive(Clone)]
pub struct MlDsaPrehashContext {
    hash: MlDsaPrehash,
    state: MlDsaPrehashState,
}

#[derive(Clone)]
enum MlDsaPrehashState {
    Hash(crate::digest::HashContext),
    Shake128(sha3::Shake128),
    Shake256(sha3::Shake256),
}

impl fmt::Debug for MlDsaPrehashContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaPrehashContext")
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

impl MlDsaPrehashContext {
    pub fn update(&mut self, message: &[u8]) {
        use sha3::digest::Update;
        match &mut self.state {
            MlDsaPrehashState::Hash(hash) => hash.update(message),
            MlDsaPrehashState::Shake128(hash) => hash.update(message),
            MlDsaPrehashState::Shake256(hash) => hash.update(message),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, XofReader};
        let mut output = vec![0; self.hash.digest_length()];
        match self.state {
            MlDsaPrehashState::Hash(hash) => return hash.finalize(),
            MlDsaPrehashState::Shake128(hash) => hash.finalize_xof().read(&mut output),
            MlDsaPrehashState::Shake256(hash) => hash.finalize_xof().read(&mut output),
        }
        output
    }
}

pub fn verify_ml_dsa(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if context.len() > 255 {
        return Err(MlDsaError::InvalidContext);
    }
    macro_rules! verify {
        ($params:ty) => {{
            let encoded = EncodedVerifyingKey::<$params>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let key = ::ml_dsa::VerifyingKey::<$params>::decode(&encoded);
            let signature = Signature::<$params>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            if key.verify_with_context(message, context, &signature) {
                Ok(())
            } else {
                Err(MlDsaError::InvalidSignature)
            }
        }};
    }
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => verify!(MlDsa44),
        MlDsaParameterSet::MlDsa65 => verify!(MlDsa65),
        MlDsaParameterSet::MlDsa87 => verify!(MlDsa87),
    }
}

pub fn verify_ml_dsa_prehash(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
    hash: MlDsaPrehash,
) -> Result<(), MlDsaError> {
    if context.len() > 255 {
        return Err(MlDsaError::InvalidContext);
    }
    let message = hash.encode(message, context)?;
    macro_rules! verify {
        ($params:ty) => {{
            let encoded = EncodedVerifyingKey::<$params>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let key = ::ml_dsa::VerifyingKey::<$params>::decode(&encoded);
            let signature = Signature::<$params>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            if key.verify_internal(&message, &signature) {
                Ok(())
            } else {
                Err(MlDsaError::InvalidSignature)
            }
        }};
    }
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => verify!(MlDsa44),
        MlDsaParameterSet::MlDsa65 => verify!(MlDsa65),
        MlDsaParameterSet::MlDsa87 => verify!(MlDsa87),
    }
}

pub fn validate_ml_dsa_public_key(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
) -> Result<(), MlDsaError> {
    // FIPS 204 pkDecode accepts every encoding of the required length: rho is
    // an arbitrary seed and t1 is a packed vector of 10-bit coefficients.
    // Constructing VerifyingKey also expands its matrix, which adds no input
    // validation and can overflow a small caller stack in unoptimized builds.
    if public_key.len() != parameter_set.public_key_length() {
        return Err(MlDsaError::InvalidPublicKey);
    }
    Ok(())
}

/// Encode a raw ML-DSA verification key as SubjectPublicKeyInfo DER.
pub fn ml_dsa_public_key_info(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    use ::ml_dsa::pkcs8::{
        SubjectPublicKeyInfoRef,
        der::{Encode, asn1::BitStringRef},
        spki::AssociatedAlgorithmIdentifier,
    };

    validate_ml_dsa_public_key(parameter_set, public_key)?;
    let algorithm = match parameter_set {
        MlDsaParameterSet::MlDsa44 => MlDsa44::ALGORITHM_IDENTIFIER,
        MlDsaParameterSet::MlDsa65 => MlDsa65::ALGORITHM_IDENTIFIER,
        MlDsaParameterSet::MlDsa87 => MlDsa87::ALGORITHM_IDENTIFIER,
    };
    let subject_public_key =
        BitStringRef::new(0, public_key).map_err(|_| MlDsaError::InvalidPublicKey)?;
    SubjectPublicKeyInfoRef {
        algorithm,
        subject_public_key,
    }
    .to_der()
    .map_err(|_| MlDsaError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn ml_dsa_prehash_streaming_preserves_cloned_state_and_chunk_boundaries() {
        let message = vec![0x42; 8193];
        for id in [1, 2, 3, 4, 7, 8, 9, 10, 11, 12] {
            let hash = MlDsaPrehash::from_id(id).unwrap();
            for chunk_size in [1, 7, 64, 136, 168, 1024] {
                let mut state = hash.context();
                state.update(&[]);
                for part in message.chunks(chunk_size) {
                    state.update(part);
                }
                assert_eq!(state.clone().finalize(), hash.digest(&message));
                assert_eq!(state.finalize(), hash.digest(&message));
            }
            assert_eq!(hash.context().finalize(), hash.digest(&[]));
        }
    }

    #[test]
    fn ml_dsa_prehash_matches_independent_hashlib_vectors() {
        assert_eq!(
            MlDsaPrehash::from_id(1).unwrap().digest(b"abc"),
            vec![
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(2).unwrap().digest(b"abc"),
            vec![
                203, 0, 117, 63, 69, 163, 94, 139, 181, 160, 61, 105, 154, 198, 80, 7, 39, 44, 50,
                171, 14, 222, 209, 99, 26, 139, 96, 90, 67, 255, 91, 237, 128, 134, 7, 43, 161,
                231, 204, 35, 88, 186, 236, 161, 52, 200, 37, 167
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(3).unwrap().digest(b"abc"),
            vec![
                221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230,
                250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42,
                39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60,
                232, 14, 42, 154, 201, 79, 165, 76, 164, 159
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(4).unwrap().digest(b"abc"),
            vec![
                35, 9, 125, 34, 52, 5, 216, 34, 134, 66, 164, 119, 189, 162, 85, 179, 42, 173, 188,
                228, 189, 160, 179, 247, 227, 108, 157, 167
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(7).unwrap().digest(b"abc"),
            vec![
                230, 66, 130, 76, 63, 140, 242, 74, 208, 146, 52, 238, 125, 60, 118, 111, 201, 163,
                165, 22, 141, 12, 148, 173, 115, 180, 111, 223
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(8).unwrap().digest(b"abc"),
            vec![
                58, 152, 93, 167, 79, 226, 37, 178, 4, 92, 23, 45, 107, 211, 144, 189, 133, 95, 8,
                110, 62, 157, 82, 91, 70, 191, 226, 69, 17, 67, 21, 50
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(9).unwrap().digest(b"abc"),
            vec![
                236, 1, 73, 130, 136, 81, 111, 201, 38, 69, 159, 88, 226, 198, 173, 141, 249, 180,
                115, 203, 15, 192, 140, 37, 150, 218, 124, 240, 228, 155, 228, 178, 152, 216, 140,
                234, 146, 122, 199, 245, 57, 241, 237, 242, 40, 55, 109, 37
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(10).unwrap().digest(b"abc"),
            vec![
                183, 81, 133, 11, 26, 87, 22, 138, 86, 147, 205, 146, 75, 107, 9, 110, 8, 246, 33,
                130, 116, 68, 247, 13, 136, 79, 93, 2, 64, 210, 113, 46, 16, 225, 22, 233, 25, 42,
                243, 201, 26, 126, 197, 118, 71, 227, 147, 64, 87, 52, 11, 76, 244, 8, 213, 165,
                101, 146, 248, 39, 78, 236, 83, 240
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(11).unwrap().digest(b"abc"),
            vec![
                88, 129, 9, 45, 216, 24, 191, 92, 248, 163, 221, 183, 147, 251, 203, 167, 64, 151,
                213, 197, 38, 166, 211, 95, 151, 184, 51, 81, 148, 15, 44, 200
            ]
        );
        assert_eq!(
            MlDsaPrehash::from_id(12).unwrap().digest(b"abc"),
            vec![
                72, 51, 102, 96, 19, 96, 168, 119, 28, 104, 99, 8, 12, 196, 17, 77, 141, 180, 69,
                48, 248, 241, 225, 238, 79, 148, 234, 55, 231, 139, 87, 57, 213, 161, 91, 239, 24,
                106, 83, 134, 199, 87, 68, 192, 82, 126, 31, 170, 159, 135, 38, 228, 98, 161, 42,
                79, 235, 6, 189, 136, 1, 231, 81, 228
            ]
        );
    }

    #[test]
    fn hash_ml_dsa_domain_separation_and_digest_lengths() {
        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let key = MlDsaPrivateKey::from_seed(parameter_set, [7; 32]);
            for id in [1, 2, 3, 4, 7, 8, 9, 10, 11, 12] {
                let hash = MlDsaPrehash::from_id(id).unwrap();
                let digest = vec![0x42; hash.digest_length()];
                let signature = key
                    .sign_prehash(&digest, b"context", hash, MlDsaRandomization::Deterministic)
                    .unwrap();
                verify_ml_dsa_prehash(
                    parameter_set,
                    &key.public_key(),
                    &digest,
                    b"context",
                    &signature,
                    hash,
                )
                .unwrap();
                assert!(
                    verify_ml_dsa(
                        parameter_set,
                        &key.public_key(),
                        &digest,
                        b"context",
                        &signature
                    )
                    .is_err()
                );
                assert!(
                    verify_ml_dsa_prehash(
                        parameter_set,
                        &key.public_key(),
                        &digest,
                        b"other",
                        &signature,
                        hash
                    )
                    .is_err()
                );
                assert!(
                    key.sign_prehash(
                        &digest[..digest.len() - 1],
                        b"context",
                        hash,
                        MlDsaRandomization::Deterministic
                    )
                    .is_err()
                );
                assert!(
                    key.sign_prehash(&digest, &[0; 256], hash, MlDsaRandomization::Deterministic)
                        .is_err()
                );
                for context in [&[][..], &[0x61; 255][..]] {
                    let signature = key
                        .sign_prehash(&digest, context, hash, MlDsaRandomization::Deterministic)
                        .unwrap();
                    verify_ml_dsa_prehash(
                        parameter_set,
                        &key.public_key(),
                        &digest,
                        context,
                        &signature,
                        hash,
                    )
                    .unwrap();
                }
                // Independent construction of FIPS 204 Algorithm 4's M-prime.
                let mut encoded = vec![
                    1, 7, b'c', b'o', b'n', b't', b'e', b'x', b't', 6, 9, 0x60, 0x86, 0x48, 1,
                    0x65, 3, 4, 2, id,
                ];
                encoded.extend_from_slice(&digest);
                let rnd = [0; 32].into();
                let expected = match &key {
                    MlDsaPrivateKey::MlDsa44(key) => key
                        .expanded_key()
                        .sign_internal(&[&encoded], &rnd)
                        .encode()
                        .to_vec(),
                    MlDsaPrivateKey::MlDsa65(key) => key
                        .expanded_key()
                        .sign_internal(&[&encoded], &rnd)
                        .encode()
                        .to_vec(),
                    MlDsaPrivateKey::MlDsa87(key) => key
                        .expanded_key()
                        .sign_internal(&[&encoded], &rnd)
                        .encode()
                        .to_vec(),
                };
                assert_eq!(signature, expected);
            }
        }
        assert!(MlDsaPrehash::from_id(0).is_none());
        assert!(MlDsaPrehash::from_id(5).is_none());
    }

    #[test]
    fn ml_kem_clones_share_key_material_until_the_last_owner_drops() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let original = MlKemPrivateKey::from_seed(parameter_set, [7; 64]);
            let cloned = original.clone();
            let shared = match (&original, &cloned) {
                (MlKemPrivateKey::MlKem512(a), MlKemPrivateKey::MlKem512(b)) => Arc::ptr_eq(a, b),
                (MlKemPrivateKey::MlKem768(a), MlKemPrivateKey::MlKem768(b)) => Arc::ptr_eq(a, b),
                (MlKemPrivateKey::MlKem1024(a), MlKemPrivateKey::MlKem1024(b)) => Arc::ptr_eq(a, b),
                _ => false,
            };
            assert!(shared);
            let (ciphertext, secret) =
                ml_kem_encapsulate(parameter_set, &original.public_key()).unwrap();
            drop(original);
            assert_eq!(cloned.decapsulate(&ciphertext).unwrap(), secret);
            macro_rules! released {
                ($key:expr) => {{
                    let weak = Arc::downgrade(&$key);
                    assert_eq!(weak.strong_count(), 1);
                    drop($key);
                    assert!(weak.upgrade().is_none());
                }};
            }
            match cloned {
                MlKemPrivateKey::MlKem512(key) => released!(key),
                MlKemPrivateKey::MlKem768(key) => released!(key),
                MlKemPrivateKey::MlKem1024(key) => released!(key),
            }
        }
    }

    #[test]
    fn every_ml_kem_parameter_set_round_trips_all_key_encodings() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let key = MlKemPrivateKey::from_seed(parameter_set, [7; 64]);
            assert_eq!(key.seed().unwrap().as_slice(), &[7; 64]);
            assert_eq!(key.public_key().len(), parameter_set.public_key_length());
            assert_eq!(
                key.expanded_private_key().len(),
                parameter_set.expanded_private_key_length()
            );
            let (ciphertext, encapsulated) =
                ml_kem_encapsulate(parameter_set, &key.public_key()).unwrap();
            assert_eq!(ciphertext.len(), parameter_set.ciphertext_length());
            assert_eq!(key.decapsulate(&ciphertext).unwrap(), encapsulated);

            let encoded = key.to_pkcs8_der().unwrap();
            let restored = MlKemPrivateKey::from_pkcs8_der(parameter_set, &encoded).unwrap();
            assert_eq!(restored.public_key(), key.public_key());
            assert!(
                !ml_kem_public_key_info(parameter_set, &key.public_key())
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn ml_dsa_44_key_generation_matches_nist_acvp_fips_204() {
        // NIST ACVP-Server, ML-DSA-keyGen-FIPS204, tgId 1 / tcId 1.
        let seed = [
            0x71, 0x94, 0xb1, 0x3c, 0x95, 0x23, 0x10, 0x10, 0xaf, 0xd2, 0xc9, 0x09, 0x99, 0x2b,
            0xd2, 0x00, 0x3b, 0xa6, 0xf4, 0x37, 0xc3, 0x88, 0x6b, 0xdb, 0xe3, 0xf6, 0xb8, 0x67,
            0xa1, 0x4b, 0xa1, 0x61,
        ];
        let key = MlDsaPrivateKey::from_seed(MlDsaParameterSet::MlDsa44, seed);
        assert_eq!(
            Sha256::digest(key.public_key()).as_slice(),
            &[
                0x83, 0x8b, 0x88, 0xb6, 0xac, 0x41, 0xe2, 0xc6, 0x06, 0x98, 0x17, 0x3e, 0x08, 0xca,
                0x17, 0x3d, 0x0b, 0x0d, 0x28, 0x39, 0x20, 0x58, 0x06, 0xe5, 0x6a, 0x8a, 0x3d, 0x53,
                0x19, 0x5f, 0x3a, 0x03,
            ]
        );
    }

    #[test]
    fn every_parameter_set_round_trips_seed_and_signatures() {
        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let key = MlDsaPrivateKey::from_seed(parameter_set, [7; 32]);
            assert_eq!(*key.seed().unwrap(), [7; 32]);
            assert_eq!(key.public_key().len(), parameter_set.public_key_length());
            let signature = key.sign_deterministic(b"message", b"context").unwrap();
            assert_eq!(signature.len(), parameter_set.signature_length());
            verify_ml_dsa(
                parameter_set,
                &key.public_key(),
                b"message",
                b"context",
                &signature,
            )
            .unwrap();

            let randomized = key
                .sign(
                    b"randomized message",
                    b"context",
                    MlDsaRandomization::Randomized,
                )
                .unwrap();
            verify_ml_dsa(
                parameter_set,
                &key.public_key(),
                b"randomized message",
                b"context",
                &randomized,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_contexts_larger_than_fips_204_allows() {
        let key = MlDsaPrivateKey::from_seed(MlDsaParameterSet::MlDsa44, [9; 32]);
        assert_eq!(
            key.sign(b"message", &[0; 256], MlDsaRandomization::HedgePreferred,),
            Err(MlDsaError::InvalidContext)
        );
    }

    fn assert_ml_kem_expanded_import_checks_pair(parameter_set: MlKemParameterSet) {
        let original = MlKemPrivateKey::from_seed(parameter_set, [7; 64]);
        let encoded = original.expanded_private_key();
        let imported = MlKemPrivateKey::from_expanded_private_key(parameter_set, &encoded).unwrap();
        assert_eq!(imported.public_key(), original.public_key());
        assert_eq!(imported.expanded_private_key(), encoded);
        assert!(imported.seed().is_none());
        for randomness in [[1; 32], [0xff; 32]] {
            let (ciphertext, expected) = ml_kem_encapsulate_deterministic(
                parameter_set,
                &original.public_key(),
                &randomness,
            )
            .unwrap();
            assert_eq!(imported.decapsulate(&ciphertext).unwrap(), expected);
        }

        // Both halves come from valid keys, and the embedded H(ek) is unchanged.
        // The dependency's structural/hash checks accept this inconsistent pair.
        let unrelated = MlKemPrivateKey::from_seed(parameter_set, [9; 64]);
        let unrelated_encoded = unrelated.expanded_private_key();
        let private_pke_length = parameter_set.public_key_length() - 32;
        let mut mismatched = encoded.clone();
        mismatched[..private_pke_length].copy_from_slice(&unrelated_encoded[..private_pke_length]);
        assert_eq!(
            MlKemPrivateKey::from_expanded_private_key(parameter_set, &mismatched).unwrap_err(),
            MlKemError::InvalidExpandedPrivateKey,
        );
    }

    #[test]
    fn ml_kem_512_expanded_import_checks_pair() {
        assert_ml_kem_expanded_import_checks_pair(MlKemParameterSet::MlKem512);
    }

    #[test]
    fn ml_kem_768_expanded_import_checks_pair() {
        assert_ml_kem_expanded_import_checks_pair(MlKemParameterSet::MlKem768);
    }

    #[test]
    fn ml_kem_1024_expanded_import_checks_pair() {
        assert_ml_kem_expanded_import_checks_pair(MlKemParameterSet::MlKem1024);
    }

    #[test]
    fn ml_kem_expanded_import_rejects_encoding_errors_before_requesting_randomness() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let original = MlKemPrivateKey::from_seed(parameter_set, [7; 64]);
            let encoded = original.expanded_private_key();
            let mut bad_hash = encoded.clone();
            let hash_offset = bad_hash.len() - 64;
            bad_hash[hash_offset] ^= 1;
            let mut bad_public = encoded.clone();
            let public_offset = parameter_set.public_key_length() - 32;
            // A public coefficient equal to q=3329 is noncanonical. Recompute
            // H(ek), so the coefficient check must reject independently of it.
            bad_public[public_offset] = 0x01;
            bad_public[public_offset + 1] = (bad_public[public_offset + 1] & 0xf0) | 0x0d;
            let hash = ::sha3::Sha3_256::digest(&bad_public[public_offset..hash_offset]);
            bad_public[hash_offset..hash_offset + 32].copy_from_slice(&hash);
            for invalid in [&encoded[..encoded.len() - 1], &bad_hash, &bad_public] {
                let result = MlKemPrivateKey::from_expanded_private_key_with_randomness(
                    parameter_set,
                    invalid,
                    |_| panic!("malformed encoding must fail before the pairwise test"),
                );
                assert_eq!(result.unwrap_err(), MlKemError::InvalidExpandedPrivateKey);
            }
        }
    }

    #[test]
    fn ml_kem_expanded_import_fails_closed_when_randomness_is_unavailable() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let encoded = MlKemPrivateKey::from_seed(parameter_set, [7; 64]).expanded_private_key();
            let result = MlKemPrivateKey::from_expanded_private_key_with_randomness(
                parameter_set,
                &encoded,
                |randomness| {
                    randomness[..16].fill(0xa5); // Also exercise a partially filled buffer on failure.
                    Err(MlKemError::RandomnessUnavailable)
                },
            );
            assert_eq!(result.unwrap_err(), MlKemError::RandomnessUnavailable);
        }
    }

    #[test]
    fn ml_kem_rejects_malformed_key_and_ciphertext_lengths() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            assert!(matches!(
                MlKemPrivateKey::from_seed_slice(parameter_set, &[0; 63]),
                Err(MlKemError::InvalidSeedLength)
            ));
            assert!(matches!(
                MlKemPrivateKey::from_expanded_private_key(
                    parameter_set,
                    &vec![0; parameter_set.expanded_private_key_length() - 1],
                ),
                Err(MlKemError::InvalidExpandedPrivateKey)
            ));
            assert_eq!(
                ml_kem_encapsulate(
                    parameter_set,
                    &vec![0; parameter_set.public_key_length() - 1],
                ),
                Err(MlKemError::InvalidPublicKey)
            );

            let key = MlKemPrivateKey::from_seed(parameter_set, [3; 64]);
            assert_eq!(
                key.decapsulate(&vec![0; parameter_set.ciphertext_length() - 1]),
                Err(MlKemError::InvalidCiphertext)
            );
        }
    }

    #[test]
    fn pqc_import_matches_rfc_examples_and_rejects_all_published_bad_keys() {
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa44,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-44-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa44,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-44-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa44,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-44-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa65,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-65-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa65,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-65-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa65,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-65-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa87,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-87-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa87,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-87-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlDsaPrivateKey::from_pkcs8_der(
            MlDsaParameterSet::MlDsa87,
            include_bytes!("../tests/data/pqc-rfc/rfc9881-87-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        assert!(
            MlDsaPrivateKey::from_pkcs8_der(
                MlDsaParameterSet::MlDsa44,
                include_bytes!("../tests/data/pqc-rfc/rfc9881-44-bad-1.der")
            )
            .is_err()
        );
        assert!(
            MlDsaPrivateKey::from_pkcs8_der(
                MlDsaParameterSet::MlDsa44,
                include_bytes!("../tests/data/pqc-rfc/rfc9881-44-bad-2.der")
            )
            .is_err()
        );
        assert!(
            MlDsaPrivateKey::from_pkcs8_der(
                MlDsaParameterSet::MlDsa44,
                include_bytes!("../tests/data/pqc-rfc/rfc9881-44-bad-3.der")
            )
            .is_err()
        );
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem512,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-512-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem512,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-512-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem512,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-512-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem768,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-768-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem768,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-768-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem768,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-768-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem1024,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-1024-seed.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        let expected = key.public_key();
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem1024,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-1024-expanded.der"),
        )
        .unwrap();
        assert!(key.seed().is_none());
        assert_eq!(key.public_key(), expected);
        let key = MlKemPrivateKey::from_pkcs8_der(
            MlKemParameterSet::MlKem1024,
            include_bytes!("../tests/data/pqc-rfc/rfc9935-1024-both.der"),
        )
        .unwrap();
        assert!(key.seed().is_some());
        assert_eq!(key.public_key(), expected);
        assert!(
            MlKemPrivateKey::from_pkcs8_der(
                MlKemParameterSet::MlKem512,
                include_bytes!("../tests/data/pqc-rfc/rfc9935-512-bad-1.der")
            )
            .is_err()
        );
        assert!(
            MlKemPrivateKey::from_pkcs8_der(
                MlKemParameterSet::MlKem512,
                include_bytes!("../tests/data/pqc-rfc/rfc9935-512-bad-2.der")
            )
            .is_err()
        );
        assert!(
            MlKemPrivateKey::from_pkcs8_der(
                MlKemParameterSet::MlKem512,
                include_bytes!("../tests/data/pqc-rfc/rfc9935-512-bad-3.der")
            )
            .is_err()
        );
        assert!(
            MlKemPrivateKey::from_pkcs8_der(
                MlKemParameterSet::MlKem512,
                include_bytes!("../tests/data/pqc-rfc/rfc9935-512-bad-4.der")
            )
            .is_err()
        );
    }

    #[test]
    fn expanded_ml_dsa_import_validates_every_parameter_set_on_small_stacks() {
        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn(move || {
                    let seeded = MlDsaPrivateKey::from_seed(parameter_set, [17; 32]);
                    let expanded = seeded.expanded_private_key();
                    let imported =
                        MlDsaPrivateKey::from_expanded_private_key(parameter_set, &expanded)
                            .unwrap();
                    assert!(imported.seed().is_none());
                    assert_eq!(imported.public_key(), seeded.public_key());
                    let signature = imported
                        .sign_deterministic(b"imported message", b"import")
                        .unwrap();
                    verify_ml_dsa(
                        parameter_set,
                        &seeded.public_key(),
                        b"imported message",
                        b"import",
                        &signature,
                    )
                    .unwrap();
                    let digest = [7; 32];
                    let signature = imported
                        .sign_prehash(
                            &digest,
                            b"import",
                            MlDsaPrehash::from_id(1).unwrap(),
                            MlDsaRandomization::Deterministic,
                        )
                        .unwrap();
                    verify_ml_dsa_prehash(
                        parameter_set,
                        &seeded.public_key(),
                        &digest,
                        b"import",
                        &signature,
                        MlDsaPrehash::from_id(1).unwrap(),
                    )
                    .unwrap();
                    let serialized =
                        crate::software_signing::SoftwareSigningKey::MlDsa(imported.clone())
                            .serialized()
                            .unwrap();
                    assert_eq!(serialized.as_slice(), expanded.as_slice());
                    let restored =
                        MlDsaPrivateKey::from_serialized(parameter_set, &serialized).unwrap();
                    assert_eq!(restored.public_key(), imported.public_key());
                    let der = imported.to_pkcs8_der().unwrap();
                    let restored = MlDsaPrivateKey::from_pkcs8_der(parameter_set, &der).unwrap();
                    assert!(restored.seed().is_none());
                    assert_eq!(restored.expanded_private_key(), expanded);
                    for offset in [0, 64, 128, expanded.len() - 1] {
                        let mut bad = expanded.clone();
                        bad[offset] ^= 1;
                        assert!(matches!(
                            MlDsaPrivateKey::from_expanded_private_key(parameter_set, &bad),
                            Err(MlDsaError::InvalidExpandedPrivateKey)
                        ));
                    }
                    let mut bad = expanded.clone();
                    bad[128] = 0xff;
                    assert!(
                        MlDsaPrivateKey::from_expanded_private_key(parameter_set, &bad).is_err()
                    );
                    assert!(
                        MlDsaPrivateKey::from_expanded_private_key(
                            parameter_set,
                            &expanded[..expanded.len() - 1]
                        )
                        .is_err()
                    );
                })
                .unwrap()
                .join()
                .unwrap();
        }
    }

    #[test]
    fn pqc_pkcs8_accepts_all_standard_choices_and_checks_redundant_material() {
        use crate::pqc_key_encoding::{self, PrivateEncoding};
        for params in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let seed = [11; 32];
            let key = MlDsaPrivateKey::from_seed(params, seed);
            let expanded = key.expanded_private_key();
            let algorithm = MlDsaPrivateKey::algorithm_for(params);
            for encoding in [
                PrivateEncoding::Seed(&seed),
                PrivateEncoding::Expanded(&expanded),
                PrivateEncoding::Both {
                    seed: &seed,
                    expanded: &expanded,
                },
            ] {
                let der =
                    pqc_key_encoding::encode(algorithm, encoding, Some(&key.public_key())).unwrap();
                let restored = MlDsaPrivateKey::from_pkcs8_der(params, &der).unwrap();
                assert_eq!(restored.public_key(), key.public_key());
            }
            let mut bad = expanded.clone();
            bad[32] ^= 1; // K does not change the public key.
            assert!(MlDsaPrivateKey::from_expanded_private_key(params, &bad).is_ok());
            let der = pqc_key_encoding::encode(
                algorithm,
                PrivateEncoding::Both {
                    seed: &seed,
                    expanded: &bad,
                },
                None,
            )
            .unwrap();
            assert!(MlDsaPrivateKey::from_pkcs8_der(params, &der).is_err());
            let other = MlDsaPrivateKey::from_seed(params, [12; 32]);
            let der = pqc_key_encoding::encode(
                algorithm,
                PrivateEncoding::Seed(&seed),
                Some(&other.public_key()),
            )
            .unwrap();
            assert!(MlDsaPrivateKey::from_pkcs8_der(params, &der).is_err());
            check_bad_pqc_der(algorithm, &key.to_pkcs8_der().unwrap(), |bad| {
                MlDsaPrivateKey::from_pkcs8_der(params, bad).is_err()
            });
        }
        for params in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let seed = [11; 64];
            let key = MlKemPrivateKey::from_seed(params, seed);
            let expanded = key.expanded_private_key();
            let algorithm = MlKemPrivateKey::algorithm_for(params);
            for encoding in [
                PrivateEncoding::Seed(&seed),
                PrivateEncoding::Expanded(&expanded),
                PrivateEncoding::Both {
                    seed: &seed,
                    expanded: &expanded,
                },
            ] {
                let der =
                    pqc_key_encoding::encode(algorithm, encoding, Some(&key.public_key())).unwrap();
                let restored = MlKemPrivateKey::from_pkcs8_der(params, &der).unwrap();
                assert_eq!(restored.expanded_private_key(), expanded);
            }
            let imported = MlKemPrivateKey::from_expanded_private_key(params, &expanded).unwrap();
            let der = imported.to_pkcs8_der().unwrap();
            let restored = MlKemPrivateKey::from_pkcs8_der(params, &der).unwrap();
            assert!(restored.seed().is_none());
            assert_eq!(restored.expanded_private_key(), expanded);
            let mut bad = expanded.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1; // z cannot be checked without seed.
            assert!(MlKemPrivateKey::from_expanded_private_key(params, &bad).is_ok());
            let der = pqc_key_encoding::encode(
                algorithm,
                PrivateEncoding::Both {
                    seed: &seed,
                    expanded: &bad,
                },
                None,
            )
            .unwrap();
            assert!(MlKemPrivateKey::from_pkcs8_der(params, &der).is_err());
            let other = MlKemPrivateKey::from_seed(params, [12; 64]);
            let der = pqc_key_encoding::encode(
                algorithm,
                PrivateEncoding::Seed(&seed),
                Some(&other.public_key()),
            )
            .unwrap();
            assert!(MlKemPrivateKey::from_pkcs8_der(params, &der).is_err());
            check_bad_pqc_der(algorithm, &key.to_pkcs8_der().unwrap(), |bad| {
                MlKemPrivateKey::from_pkcs8_der(params, bad).is_err()
            });
        }
    }

    fn check_bad_pqc_der(
        algorithm: ml_dsa::pkcs8::AlgorithmIdentifierRef<'static>,
        valid: &[u8],
        rejects: impl Fn(&[u8]) -> bool,
    ) {
        use ml_dsa::pkcs8::{
            PrivateKeyInfoRef,
            der::{
                Decode, Encode,
                asn1::{AnyRef, OctetStringRef},
            },
        };
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(rejects(&trailing));
        let mut info = PrivateKeyInfoRef::from_der(valid).unwrap();
        info.algorithm.parameters = Some(AnyRef::NULL);
        assert!(rejects(&info.to_der().unwrap()));
        info.algorithm = algorithm;
        info.algorithm.oid = ml_dsa::pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");
        assert!(rejects(&info.to_der().unwrap()));
        info.algorithm = algorithm;
        let mut private = info.private_key.as_bytes().to_vec();
        private.push(0);
        info.private_key = OctetStringRef::new(&private).unwrap();
        assert!(rejects(&info.to_der().unwrap()));
    }

    #[test]
    fn ml_dsa_keys_fit_small_stacks_and_share_storage() {
        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let (seeded, restored, generated) = std::thread::Builder::new()
                .name(format!("{parameter_set:?}-construction-caller"))
                .stack_size(512 * 1024)
                .spawn(move || {
                    let seeded = MlDsaPrivateKey::from_seed(parameter_set, [7; 32]);
                    let cloned = seeded.clone();
                    let same_allocation = match (&seeded, &cloned) {
                        (MlDsaPrivateKey::MlDsa44(a), MlDsaPrivateKey::MlDsa44(b)) => {
                            Arc::ptr_eq(a, b)
                        }
                        (MlDsaPrivateKey::MlDsa65(a), MlDsaPrivateKey::MlDsa65(b)) => {
                            Arc::ptr_eq(a, b)
                        }
                        (MlDsaPrivateKey::MlDsa87(a), MlDsaPrivateKey::MlDsa87(b)) => {
                            Arc::ptr_eq(a, b)
                        }
                        _ => false,
                    };
                    assert!(same_allocation);
                    drop(seeded);
                    let seeded = cloned;
                    let encoded = seeded.to_pkcs8_der().unwrap();
                    let restored =
                        MlDsaPrivateKey::from_pkcs8_der(parameter_set, &encoded).unwrap();
                    let generated = MlDsaPrivateKey::generate(parameter_set).unwrap();
                    assert!(matches!(
                        MlDsaPrivateKey::from_pkcs8_der(parameter_set, &[0; 16]),
                        Err(MlDsaError::InvalidPrivateKey)
                    ));
                    (seeded, restored, generated)
                })
                .unwrap()
                .join()
                .unwrap();

            assert_eq!(*seeded.seed().unwrap(), [7; 32]);
            assert_eq!(*restored.seed().unwrap(), [7; 32]);
            assert_eq!(seeded.public_key(), restored.public_key());
            // Exercise returned keys after the construction caller has exited.
            std::thread::Builder::new()
                .name(format!("{parameter_set:?}-crypto-caller"))
                .stack_size(512 * 1024)
                .spawn(move || {
                    for key in [seeded, restored, generated] {
                        let public = key.public_key();
                        let signature = key.sign_deterministic(b"message", b"context").unwrap();
                        verify_ml_dsa(parameter_set, &public, b"message", b"context", &signature)
                            .unwrap();
                        assert_eq!(
                            verify_ml_dsa(
                                parameter_set,
                                &public,
                                b"changed",
                                b"context",
                                &signature
                            ),
                            Err(MlDsaError::InvalidSignature)
                        );
                    }
                })
                .unwrap()
                .join()
                .unwrap();
        }
    }

    #[test]
    fn ml_dsa_public_metadata_fits_small_stacks_and_matches_upstream_der() {
        use ::ml_dsa::pkcs8::EncodePublicKey;

        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            for fill in [0, 0xff] {
                let public_key = vec![fill; parameter_set.public_key_length()];
                macro_rules! reference {
                    ($params:ty) => {{
                        let encoded =
                            EncodedVerifyingKey::<$params>::try_from(public_key.as_slice())
                                .unwrap();
                        ::ml_dsa::VerifyingKey::<$params>::decode(&encoded)
                            .to_public_key_der()
                            .unwrap()
                            .as_bytes()
                            .to_vec()
                    }};
                }
                let expected = match parameter_set {
                    MlDsaParameterSet::MlDsa44 => reference!(MlDsa44),
                    MlDsaParameterSet::MlDsa65 => reference!(MlDsa65),
                    MlDsaParameterSet::MlDsa87 => reference!(MlDsa87),
                };
                let actual = std::thread::Builder::new()
                    .stack_size(64 * 1024)
                    .spawn(move || {
                        validate_ml_dsa_public_key(parameter_set, &public_key).unwrap();
                        ml_dsa_public_key_info(parameter_set, &public_key).unwrap()
                    })
                    .unwrap()
                    .join()
                    .unwrap();
                assert_eq!(actual, expected);
            }
            for length in [
                0,
                parameter_set.public_key_length() - 1,
                parameter_set.public_key_length() + 1,
            ] {
                let invalid = vec![0; length];
                assert_eq!(
                    validate_ml_dsa_public_key(parameter_set, &invalid),
                    Err(MlDsaError::InvalidPublicKey)
                );
                assert_eq!(
                    ml_dsa_public_key_info(parameter_set, &invalid),
                    Err(MlDsaError::InvalidPublicKey)
                );
            }
        }
    }

    #[test]
    fn ml_dsa_rejects_malformed_keys_signatures_and_messages() {
        let parameter_set = MlDsaParameterSet::MlDsa44;
        assert!(matches!(
            MlDsaPrivateKey::from_seed_slice(parameter_set, &[0; 31]),
            Err(MlDsaError::InvalidSeedLength)
        ));
        assert_eq!(
            validate_ml_dsa_public_key(
                parameter_set,
                &vec![0; parameter_set.public_key_length() - 1],
            ),
            Err(MlDsaError::InvalidPublicKey)
        );

        let key = MlDsaPrivateKey::from_seed(parameter_set, [5; 32]);
        let public_key = key.public_key();
        let mut signature = key.sign_deterministic(b"message", b"context").unwrap();
        signature[0] ^= 1;
        assert_eq!(
            verify_ml_dsa(
                parameter_set,
                &public_key,
                b"message",
                b"context",
                &signature,
            ),
            Err(MlDsaError::InvalidSignature)
        );
        assert_eq!(
            verify_ml_dsa(
                parameter_set,
                &public_key,
                b"message",
                b"context",
                &signature[..signature.len() - 1],
            ),
            Err(MlDsaError::InvalidSignature)
        );
    }
    #[test]
    fn raw_private_encodings_share_component_validation_and_preserve_seed_availability() {
        macro_rules! check {
            ($key:ident, $params:expr, $size:expr) => {
                for parameters in $params {
                    let seed = [7; $size];
                    let original = $key::from_seed(parameters, seed);
                    let expanded = original.expanded_private_key();
                    let both = Zeroizing::new([seed.as_slice(), expanded.as_slice()].concat());
                    for (encoded, has_seed) in [
                        (seed.as_slice(), true),
                        (expanded.as_slice(), false),
                        (both.as_slice(), true),
                    ] {
                        let key = $key::from_serialized(parameters, encoded).unwrap();
                        assert_eq!(key.public_key(), original.public_key());
                        assert_eq!(key.expanded_private_key(), expanded);
                        assert_eq!(key.seed().is_some(), has_seed);
                        let stored = key.serialized();
                        assert_eq!(
                            stored.as_slice(),
                            if has_seed {
                                seed.as_slice()
                            } else {
                                expanded.as_slice()
                            }
                        );
                        let restored = $key::from_serialized(parameters, &stored).unwrap();
                        assert_eq!(restored.seed().is_some(), has_seed);
                        assert_eq!(restored.expanded_private_key(), expanded);
                        assert!(
                            $key::from_serialized(parameters, &encoded[..encoded.len() - 1])
                                .is_err()
                        );
                    }
                    let mut inconsistent = both;
                    inconsistent[0] ^= 1;
                    assert!($key::from_serialized(parameters, &inconsistent).is_err());
                    assert!($key::from_components(parameters, None, None).is_err());
                }
            };
        }
        check!(
            MlDsaPrivateKey,
            [
                MlDsaParameterSet::MlDsa44,
                MlDsaParameterSet::MlDsa65,
                MlDsaParameterSet::MlDsa87
            ],
            32
        );
        check!(
            MlKemPrivateKey,
            [
                MlKemParameterSet::MlKem512,
                MlKemParameterSet::MlKem768,
                MlKemParameterSet::MlKem1024
            ],
            64
        );
    }
}
