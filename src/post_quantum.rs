//! Role-neutral post-quantum key operations shared by virtual applets.
//!
//! Protocol-specific identifiers, encodings, policy, and error mapping belong
//! in their callers. This module deliberately operates on raw FIPS 204 keys,
//! messages, contexts, and signatures so it can also be reused by `pkcs11rs`.

use ::ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Seed, Signature, SigningKey};
use signature::Keypair;
use std::fmt;
use zeroize::Zeroizing;

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

#[derive(Clone)]
pub enum MlKemPrivateKey {
    MlKem512(::ml_kem::DecapsulationKey<::ml_kem::MlKem512>),
    MlKem768(::ml_kem::DecapsulationKey<::ml_kem::MlKem768>),
    MlKem1024(::ml_kem::DecapsulationKey<::ml_kem::MlKem1024>),
}

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemPrivateKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}

impl MlKemPrivateKey {
    pub fn generate(parameter_set: MlKemParameterSet) -> Result<Self, MlKemError> {
        let mut seed = Zeroizing::new([0u8; 64]);
        getrandom::fill(seed.as_mut()).map_err(|_| MlKemError::RandomnessUnavailable)?;
        Ok(Self::from_seed(parameter_set, *seed))
    }

    pub fn from_seed(parameter_set: MlKemParameterSet, seed: [u8; 64]) -> Self {
        let seed = ::ml_kem::Seed::from(seed);
        match parameter_set {
            MlKemParameterSet::MlKem512 => {
                Self::MlKem512(::ml_kem::DecapsulationKey::from_seed(seed))
            }
            MlKemParameterSet::MlKem768 => {
                Self::MlKem768(::ml_kem::DecapsulationKey::from_seed(seed))
            }
            MlKemParameterSet::MlKem1024 => {
                Self::MlKem1024(::ml_kem::DecapsulationKey::from_seed(seed))
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

    #[allow(deprecated)]
    pub fn from_expanded_private_key(
        parameter_set: MlKemParameterSet,
        expanded: &[u8],
    ) -> Result<Self, MlKemError> {
        macro_rules! decode {
            ($params:ty, $variant:ident) => {{
                let expanded = ::ml_kem::ExpandedDecapsulationKey::<$params>::try_from(expanded)
                    .map_err(|_| MlKemError::InvalidExpandedPrivateKey)?;
                ::ml_kem::ExpandedKeyEncoding::from_expanded_bytes(&expanded)
                    .map(Self::$variant)
                    .map_err(|_| MlKemError::InvalidExpandedPrivateKey)
            }};
        }
        match parameter_set {
            MlKemParameterSet::MlKem512 => decode!(::ml_kem::MlKem512, MlKem512),
            MlKemParameterSet::MlKem768 => decode!(::ml_kem::MlKem768, MlKem768),
            MlKemParameterSet::MlKem1024 => decode!(::ml_kem::MlKem1024, MlKem1024),
        }
    }

    pub fn from_pkcs8_der(
        parameter_set: MlKemParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlKemError> {
        use ::ml_kem::pkcs8::DecodePrivateKey;
        match parameter_set {
            MlKemParameterSet::MlKem512 => {
                ::ml_kem::DecapsulationKey::<::ml_kem::MlKem512>::from_pkcs8_der(encoded)
                    .map(Self::MlKem512)
            }
            MlKemParameterSet::MlKem768 => {
                ::ml_kem::DecapsulationKey::<::ml_kem::MlKem768>::from_pkcs8_der(encoded)
                    .map(Self::MlKem768)
            }
            MlKemParameterSet::MlKem1024 => {
                ::ml_kem::DecapsulationKey::<::ml_kem::MlKem1024>::from_pkcs8_der(encoded)
                    .map(Self::MlKem1024)
            }
        }
        .map_err(|_| MlKemError::InvalidPrivateKey)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, MlKemError> {
        use ::ml_kem::pkcs8::EncodePrivateKey;
        let document = match self {
            Self::MlKem512(key) => key.to_pkcs8_der(),
            Self::MlKem768(key) => key.to_pkcs8_der(),
            Self::MlKem1024(key) => key.to_pkcs8_der(),
        }
        .map_err(|_| MlKemError::EncodingFailed)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
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

/// An ML-DSA private key with its expanded form cached by RustCrypto.
#[derive(Clone)]
pub enum MlDsaPrivateKey {
    MlDsa44(SigningKey<MlDsa44>),
    MlDsa65(SigningKey<MlDsa65>),
    MlDsa87(SigningKey<MlDsa87>),
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaPrivateKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}

impl MlDsaPrivateKey {
    pub fn from_pkcs8_der(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        use ::ml_dsa::pkcs8::DecodePrivateKey;
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => {
                SigningKey::<MlDsa44>::from_pkcs8_der(encoded).map(Self::MlDsa44)
            }
            MlDsaParameterSet::MlDsa65 => {
                SigningKey::<MlDsa65>::from_pkcs8_der(encoded).map(Self::MlDsa65)
            }
            MlDsaParameterSet::MlDsa87 => {
                SigningKey::<MlDsa87>::from_pkcs8_der(encoded).map(Self::MlDsa87)
            }
        }
        .map_err(|_| MlDsaError::InvalidSeedLength)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, MlDsaError> {
        use ::ml_dsa::pkcs8::EncodePrivateKey;
        let document = match self {
            Self::MlDsa44(key) => key.to_pkcs8_der(),
            Self::MlDsa65(key) => key.to_pkcs8_der(),
            Self::MlDsa87(key) => key.to_pkcs8_der(),
        }
        .map_err(|_| MlDsaError::InvalidSeedLength)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    pub fn generate(parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| MlDsaError::RandomnessUnavailable)?;
        Ok(Self::from_seed(parameter_set, *seed))
    }

    pub fn from_seed(parameter_set: MlDsaParameterSet, seed: [u8; 32]) -> Self {
        let seed = Seed::from(seed);
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => Self::MlDsa44(SigningKey::from_seed(&seed)),
            MlDsaParameterSet::MlDsa65 => Self::MlDsa65(SigningKey::from_seed(&seed)),
            MlDsaParameterSet::MlDsa87 => Self::MlDsa87(SigningKey::from_seed(&seed)),
        }
    }

    pub fn from_seed_slice(
        parameter_set: MlDsaParameterSet,
        seed: &[u8],
    ) -> Result<Self, MlDsaError> {
        let seed = seed.try_into().map_err(|_| MlDsaError::InvalidSeedLength)?;
        Ok(Self::from_seed(parameter_set, seed))
    }

    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        match self {
            Self::MlDsa44(_) => MlDsaParameterSet::MlDsa44,
            Self::MlDsa65(_) => MlDsaParameterSet::MlDsa65,
            Self::MlDsa87(_) => MlDsaParameterSet::MlDsa87,
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        let bytes = match self {
            Self::MlDsa44(key) => key.as_seed(),
            Self::MlDsa65(key) => key.as_seed(),
            Self::MlDsa87(key) => key.as_seed(),
        };
        Zeroizing::new((*bytes).into())
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
        match self {
            Self::MlDsa44(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa65(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa87(key) => key.verifying_key().encode().to_vec(),
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

pub fn validate_ml_dsa_public_key(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
) -> Result<(), MlDsaError> {
    macro_rules! validate {
        ($params:ty) => {{
            let encoded = EncodedVerifyingKey::<$params>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let _ = ::ml_dsa::VerifyingKey::<$params>::decode(&encoded);
            Ok(())
        }};
    }
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => validate!(MlDsa44),
        MlDsaParameterSet::MlDsa65 => validate!(MlDsa65),
        MlDsaParameterSet::MlDsa87 => validate!(MlDsa87),
    }
}

/// Encode a raw ML-DSA verification key as SubjectPublicKeyInfo DER.
pub fn ml_dsa_public_key_info(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    macro_rules! encode {
        ($params:ty) => {{
            use ::ml_dsa::pkcs8::EncodePublicKey;
            let encoded = EncodedVerifyingKey::<$params>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            ::ml_dsa::VerifyingKey::<$params>::decode(&encoded)
                .to_public_key_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|_| MlDsaError::InvalidPublicKey)
        }};
    }
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => encode!(MlDsa44),
        MlDsaParameterSet::MlDsa65 => encode!(MlDsa65),
        MlDsaParameterSet::MlDsa87 => encode!(MlDsa87),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

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
            assert!(!ml_kem_public_key_info(parameter_set, &key.public_key())
                .unwrap()
                .is_empty());
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
            assert_eq!(*key.seed(), [7; 32]);
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
}
