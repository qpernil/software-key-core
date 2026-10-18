//! The shared RSA creation boundary. Generate/import validates key quality and
//! performs a pair-wise consistency test; trusted restoration is explicit.
//! Protocol size/exponent policy is intentionally separate. See
//! `docs/rsa-key-validation.md` for NIST references and assurance limits.

use crate::rsa_private_validation::{
    RsaPrivateValidationError, validate_rsa_private_key, validation_strength,
};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::DecodePrivateKey,
    rand_core::CryptoRngCore,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use std::{fmt, ops::Deref, sync::Arc};
use zeroize::ZeroizeOnDrop;

/// An immutable RSA key whose construction stays inside this module.
/// A raw RustCrypto private key cannot be inserted into a software token key.
///
/// ```compile_fail
/// use software_key_core::software_signing::SoftwareSigningKey;
/// let raw = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
/// let unchecked = SoftwareSigningKey::Rsa(std::sync::Arc::new(raw));
/// ```
#[derive(Clone)]
pub struct RsaKey {
    key: Arc<RsaPrivateKey>,
    validated: bool,
}
impl ZeroizeOnDrop for RsaKey {}
impl fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKey")
            .field("bits", &self.key.n().bits())
            .finish_non_exhaustive()
    }
}
impl Deref for RsaKey {
    type Target = Arc<RsaPrivateKey>;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl RsaKey {
    pub fn modulus_bits(&self) -> usize {
        self.key.n().bits()
    }
    pub fn generate(bits: usize) -> Result<Self, RsaPrivateValidationError> {
        Self::generate_with_rng(&mut rsa::rand_core::OsRng, bits)
    }
    /// Caller-supplied cryptographic RNG, also useful for reproducible benchmarks.
    pub fn generate_with_rng(
        rng: &mut impl CryptoRngCore,
        bits: usize,
    ) -> Result<Self, RsaPrivateValidationError> {
        validation_strength(bits).ok_or(RsaPrivateValidationError::InvalidPrivateKey)?;
        let generated = RsaPrivateKey::new(rng, bits)
            .map_err(|_| RsaPrivateValidationError::RandomnessUnavailable)?;
        Self::finish_import(generated)
    }
    pub fn import_primes(
        p: BigUint,
        q: BigUint,
        exponent: BigUint,
    ) -> Result<Self, RsaPrivateValidationError> {
        let restored = Self::restore_primes(p, q, exponent)?;
        let key = Arc::try_unwrap(restored.key).unwrap_or_else(|key| (*key).clone());
        Self::admit_normalized(key)
    }
    pub fn import_components(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        primes: Vec<BigUint>,
    ) -> Result<Self, RsaPrivateValidationError> {
        use RsaPrivateValidationError::InvalidPrivateKey;
        validation_strength(n.bits()).ok_or(InvalidPrivateKey)?;
        if e.bits() > 256
            || d.bits() > n.bits()
            || primes.len() == 1
            || primes.len() > 2
            || primes.iter().any(|p| p.bits() > n.bits())
        {
            return Err(InvalidPrivateKey);
        }
        RsaPublicKey::new_with_max_size(
            n.clone(),
            e.clone(),
            crate::rsa_private_validation::MAX_RSA_BITS,
        )
        .map_err(|_| InvalidPrivateKey)?;
        let key = RsaPrivateKey::from_components(n, e, d, primes).map_err(|_| InvalidPrivateKey)?;
        Self::finish_import(key)
    }
    pub fn import_pkcs8(encoded: &[u8]) -> Result<Self, RsaPrivateValidationError> {
        let restored = Self::restore_pkcs8(encoded)?;
        Self::finish_import((*restored.key).clone())
    }
    /// Validate a restored boundary object before admitting it as a new import.
    /// Already validated immutable handles do not repeat primality testing.
    pub fn validate_for_import(&self) -> Result<Self, RsaPrivateValidationError> {
        if self.validated {
            return Ok(self.clone());
        }
        Self::finish_import((*self.key).clone())
    }
    fn finish_import(key: RsaPrivateKey) -> Result<Self, RsaPrivateValidationError> {
        use RsaPrivateValidationError::InvalidPrivateKey;
        let bits = key.n().bits();
        validation_strength(bits).ok_or(InvalidPrivateKey)?;
        if key.primes().len() != 2 {
            return Err(InvalidPrivateKey);
        }
        // The parser checks supplied n/e/d for algebraic consistency. Normalize
        // the private exponent and derive CRT parameters; discard supplied CRT.
        let mut normalized = RsaPrivateKey::from_p_q(
            key.primes()[0].clone(),
            key.primes()[1].clone(),
            key.e().clone(),
        )
        .map_err(|_| InvalidPrivateKey)?;
        normalized.precompute().map_err(|_| InvalidPrivateKey)?;
        Self::admit_normalized(normalized)
    }
    fn admit_normalized(key: RsaPrivateKey) -> Result<Self, RsaPrivateValidationError> {
        validate_rsa_private_key(&key, key.n().bits())?;
        Ok(Self {
            key: Arc::new(key),
            validated: true,
        })
    }
    /// Trusted state only: parse/reconstruct without repeating primality or PCT.
    pub fn restore_primes(
        p: BigUint,
        q: BigUint,
        e: BigUint,
    ) -> Result<Self, RsaPrivateValidationError> {
        use RsaPrivateValidationError::InvalidPrivateKey;
        if p.bits() > crate::rsa_private_validation::MAX_RSA_BITS / 2
            || q.bits() > crate::rsa_private_validation::MAX_RSA_BITS / 2
        {
            return Err(InvalidPrivateKey);
        }
        let key = RsaPrivateKey::from_p_q(p, q, e).map_err(|_| InvalidPrivateKey)?;
        Ok(Self {
            key: Arc::new(key),
            validated: false,
        })
    }
    /// Trusted persisted state only. Untrusted PKCS#8 must use `import_pkcs8`.
    pub fn restore_pkcs8(encoded: &[u8]) -> Result<Self, RsaPrivateValidationError> {
        let key = RsaPrivateKey::from_pkcs8_der(encoded)
            .map_err(|_| RsaPrivateValidationError::InvalidPrivateKey)?;
        Ok(Self {
            key: Arc::new(key),
            validated: false,
        })
    }
    /// Trusted software-token persistence format.
    pub fn restore_pkcs1(encoded: &[u8]) -> Result<Self, RsaPrivateValidationError> {
        let key = RsaPrivateKey::from_pkcs1_der(encoded)
            .map_err(|_| RsaPrivateValidationError::InvalidPrivateKey)?;
        Ok(Self {
            key: Arc::new(key),
            validated: false,
        })
    }
}

/// Public-only imports use SP 800-89 §5.3.3 partial validation. Public-key
/// projection and ordinary verification do not call this import operation.
pub fn import_public(
    n: BigUint,
    e: BigUint,
) -> Result<RsaPublicKey, crate::rsa_public_validation::RsaPublicValidationError> {
    let key = RsaPublicKey::new_with_max_size(n, e, crate::rsa_private_validation::MAX_RSA_BITS)
        .map_err(|_| crate::rsa_public_validation::RsaPublicValidationError::InvalidPublicKey)?;
    crate::rsa_public_validation::validate_rsa_public_key(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        key.n().bits(),
    )?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;

    #[test]
    fn quality_validation_is_separate_from_nist_acceptance() {
        use crate::rsa_private_validation::{check_nist_acceptance, validation_strength};
        for (bits, strength) in [
            (1024, 112),
            (2048, 112),
            (3072, 128),
            (4096, 152),
            (6144, 176),
            (8192, 200),
        ] {
            assert_eq!(validation_strength(bits), Some(strength));
        }
        for bits in (1024..=4096).step_by(256) {
            assert!(validation_strength(bits).is_some());
        }
        assert!(check_nist_acceptance(2304, &BigUint::from(65537u32)).is_ok());
        assert!(check_nist_acceptance(1024, &BigUint::from(65537u32)).is_err());
        assert!(check_nist_acceptance(2049, &BigUint::from(65537u32)).is_err());
        let odd = RsaKey::generate(1025).unwrap();
        assert_eq!(odd.modulus_bits(), 1025);
        import_public(odd.n().clone(), odd.e().clone()).unwrap();
        assert!(check_nist_acceptance(2048, &BigUint::from(3u8)).is_err());
        // The same mathematical checks remain useful for a legacy size/exponent.
        let raw =
            RsaPrivateKey::new_with_exp(&mut rsa::rand_core::OsRng, 1024, &BigUint::from(3u8))
                .unwrap();
        let key = RsaKey::import_components(
            raw.n().clone(),
            raw.e().clone(),
            raw.d().clone(),
            raw.primes().to_vec(),
        )
        .unwrap();
        assert!(key.validated);
        assert_eq!(key.e(), &BigUint::from(3u8));
        crate::rsa_public_validation::validate_rsa_public_key(
            &key.n().to_bytes_be(),
            &key.e().to_bytes_be(),
            1024,
        )
        .unwrap();
    }

    #[test]
    fn pkcs8_discards_supplied_crt_and_normalizes_private_exponent() {
        let raw = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let encoded = raw.to_pkcs8_der().unwrap();
        let info = rsa::pkcs8::PrivateKeyInfo::try_from(encoded.as_bytes()).unwrap();
        let fields = rsa::pkcs1::RsaPrivateKey::try_from(info.private_key).unwrap();
        let offsets = [
            fields.exponent1.as_bytes(),
            fields.exponent2.as_bytes(),
            fields.coefficient.as_bytes(),
        ]
        .map(|field| {
            encoded
                .as_bytes()
                .windows(field.len())
                .position(|part| part == field)
                .unwrap()
                + field.len()
                - 1
        });
        let mut changed = encoded.as_bytes().to_vec();
        for offset in offsets {
            changed[offset] ^= 1;
        }
        let imported = RsaKey::import_pkcs8(&changed).unwrap();
        assert_eq!(imported.n(), raw.n());
        assert_eq!(imported.e(), raw.e());
        assert_eq!(imported.dp(), raw.dp());
        assert_eq!(imported.dq(), raw.dq());
        assert_eq!(imported.qinv(), raw.qinv());
        assert!(imported.validated);
        let restored = RsaKey::restore_pkcs8(&changed).unwrap();
        assert!(!restored.validated);
        assert!(restored.validate_for_import().unwrap().validated);
    }

    #[test]
    fn every_private_import_rejects_algebraically_consistent_composite_factors() {
        let valid = RsaKey::generate(1024).unwrap();
        let p = (BigUint::from(1u8) << 512) - 1u8;
        let q = valid.primes()[1].clone();
        let raw = RsaPrivateKey::from_p_q(p.clone(), q.clone(), valid.e().clone()).unwrap();
        raw.validate().unwrap();
        assert!(RsaKey::import_primes(p.clone(), q.clone(), valid.e().clone()).is_err());
        assert!(
            RsaKey::import_components(
                raw.n().clone(),
                raw.e().clone(),
                raw.d().clone(),
                raw.primes().to_vec()
            )
            .is_err()
        );
        assert!(
            RsaKey::import_components(
                raw.n().clone(),
                raw.e().clone(),
                raw.d().clone(),
                Vec::new()
            )
            .is_err()
        );
        assert!(RsaKey::import_pkcs8(raw.to_pkcs8_der().unwrap().as_bytes()).is_err());
        let restored = RsaKey::restore_primes(p, q, valid.e().clone()).unwrap();
        assert!(restored.validate_for_import().is_err());
    }

    #[test]
    fn independent_published_private_keys_pass_all_import_encodings() {
        use std::io::Read;
        for fixture in [
            include_bytes!(
                "../tests/vectors/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json.gz"
            )
            .as_slice(),
            include_bytes!(
                "../tests/vectors/wycheproof/rsa_oaep_3072_sha256_mgf1sha256_test.json.gz"
            )
            .as_slice(),
            include_bytes!(
                "../tests/vectors/wycheproof/rsa_oaep_4096_sha256_mgf1sha256_test.json.gz"
            )
            .as_slice(),
        ] {
            let mut json = String::new();
            flate2::read::GzDecoder::new(fixture)
                .read_to_string(&mut json)
                .unwrap();
            let data: serde_json::Value = serde_json::from_str(&json).unwrap();
            let hex = data["testGroups"][0]["privateKeyPkcs8"].as_str().unwrap();
            let encoded: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let key = RsaKey::import_pkcs8(&encoded).unwrap();
            let rebuilt = RsaKey::import_primes(
                key.primes()[0].clone(),
                key.primes()[1].clone(),
                key.e().clone(),
            )
            .unwrap();
            assert_eq!(key.n(), rebuilt.n());
        }
    }
}
