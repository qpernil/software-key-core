//! RSA private-key import validation, SP 800-56B Rev. 2 §6.4.1.2.2.
//!
//! This is an explicit import policy, not an implicit check on every RSA use.
//! Ordinary algebraic consistency and a pair-wise operation cannot establish
//! primality. The importer must also have assurance of trusted key generation
//! (§6.4.1.1); validation cannot establish provenance or generation entropy.

use num_integer::Integer;
use rsa::{
    BigUint, RsaPrivateKey,
    rand_core::RngCore,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPrivateValidationError {
    InvalidPrivateKey,
    RandomnessUnavailable,
}

/// Work bounds for this implementation; protocol acceptance remains with callers.
pub const MIN_RSA_BITS: usize = 512;
pub const MAX_RSA_BITS: usize = 16384;

/// SP 800-56B Rev. 2 Appendix D, rounded to the nearest multiple of eight.
/// Legacy sizes receive at least the 112-bit primality-test assurance level;
/// this does not assert that their modulus offers 112-bit security.
pub fn validation_strength(bits: usize) -> Option<usize> {
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
        return None;
    }
    let x = bits as f64 * std::f64::consts::LN_2;
    let estimate = (1.923 * x.cbrt() * x.ln().powf(2.0 / 3.0) - 4.69) / std::f64::consts::LN_2;
    Some(((estimate / 8.0).round() as usize * 8).max(112))
}

/// Separate SP 800-56B acceptance policy, not implicit in mathematical validation.
pub fn check_nist_acceptance(
    bits: usize,
    exponent: &BigUint,
) -> Result<(), RsaPrivateValidationError> {
    if bits < 2048
        || !bits.is_multiple_of(2)
        || validation_strength(bits).is_none()
        || exponent < &BigUint::from(65537u32)
        || exponent.bits() > 256
        || exponent.is_even()
    {
        return Err(RsaPrivateValidationError::InvalidPrivateKey);
    }
    Ok(())
}

/// Validate two-prime RSA key quality independently of size/exponent acceptance policy.
///
/// SP 800-56B Rev. 2 §6.4.1.2.2 incorporates §6.4.1.2.1, omitting factor
/// recovery because p and q are supplied. §6.4.1.1 additionally specifies a
/// pair-wise consistency test. This function performs both at import time.
/// The caller retains authorization, persistence and trusted-generation policy.
pub fn validate_rsa_private_key(
    key: &RsaPrivateKey,
    bits: usize,
) -> Result<(), RsaPrivateValidationError> {
    validate_with_rng(key, bits, &mut rsa::rand_core::OsRng)
}

fn validate_with_rng(
    key: &RsaPrivateKey,
    bits: usize,
    rng: &mut impl RngCore,
) -> Result<(), RsaPrivateValidationError> {
    use RsaPrivateValidationError::InvalidPrivateKey;
    // §6.4.1.2.2 / §6.4.1.4.2: validate the prime-factor representation.
    // The caller separately enforces the intended size and exponent policy.
    let strength = validation_strength(bits).ok_or(InvalidPrivateKey)?;
    if key.n().bits() != bits
        || key.e() < &BigUint::from(3u8)
        || key.e().is_even()
        || key.e().bits() > 256
        || key.primes().len() != 2
    {
        return Err(InvalidPrivateKey);
    }
    let p = &key.primes()[0];
    let q = &key.primes()[1];
    let one = BigUint::from(1u8);
    // §6.4.1.2.1 step 5(a–c). Even moduli have equal factor widths.
    // For legacy odd-width moduli, adapt to floor/ceil half-width factors;
    // the separate NIST acceptance predicate rejects odd modulus lengths.
    let p_bits = p.bits();
    let q_bits = q.bits();
    if p_bits + q_bits != bits
        || p_bits.abs_diff(q_bits) > 1
        || p.is_even()
        || q.is_even()
        || *Zeroizing::new(p * p) < (&one << (2 * p_bits - 1))
        || *Zeroizing::new(q * q) < (&one << (2 * q_bits - 1))
        || *Zeroizing::new(p * q) != *key.n()
    {
        return Err(InvalidPrivateKey);
    }
    let difference = Zeroizing::new(if p > q { p - q } else { q - p });
    if *difference <= &one << (bits / 2 - 100) {
        return Err(InvalidPrivateKey);
    }
    let pm1 = Zeroizing::new(p - 1u8);
    let qm1 = Zeroizing::new(q - 1u8);
    if *Zeroizing::new(pm1.gcd(key.e())) != one || *Zeroizing::new(qm1.gcd(key.e())) != one {
        return Err(InvalidPrivateKey);
    }
    // Step 6: d is the canonical inverse modulo lcm(p-1,q-1), with a
    // lower bound. Algebraically equivalent, larger d values are rejected.
    let lambda = Zeroizing::new(pm1.lcm(&qm1));
    let de = Zeroizing::new(key.d() * key.e());
    if key.d() <= &(&one << (bits / 2))
        || key.d() >= &*lambda
        || *Zeroizing::new(&*de % &*lambda) != one
    {
        return Err(InvalidPrivateKey);
    }
    // Step 5(f–g): FIPS 186-5 §B.3.1 Miller–Rabin, independent uniform
    // random bases, worst-case false-prime probability <= 4^-rounds.
    // One additional round is a conservative implementation choice: the union
    // bound for either factor being falsely accepted is then below 2^-ES(bits).
    // This margin is not a separately mandated FIPS test.
    let rounds = strength.div_ceil(2) + 1;
    if !probable_prime(p, rounds, rng)? || !probable_prime(q, rounds, rng)? {
        return Err(InvalidPrivateKey);
    }
    // §6.4.1.1 step 2: m = (m^e)^d mod n, 1 < m < n-1.
    // Use the existing blinded private operation, including its fault check.
    let m = BigUint::from(2u8);
    let ciphertext = m.modpow(key.e(), key.n());
    let recovered = Zeroizing::new(
        rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut rsa::rand_core::OsRng), &ciphertext)
            .map_err(|_| InvalidPrivateKey)?,
    );
    if *recovered != m {
        return Err(InvalidPrivateKey);
    }
    Ok(())
}

fn probable_prime(
    n: &BigUint,
    rounds: usize,
    rng: &mut impl RngCore,
) -> Result<bool, RsaPrivateValidationError> {
    let one = BigUint::from(1u8);
    if n <= &BigUint::from(3u8) {
        return Ok(n == &BigUint::from(2u8) || n == &BigUint::from(3u8));
    }
    if n.is_even() {
        return Ok(false);
    }
    let upper = Zeroizing::new(n - 1u8);
    let a = upper.trailing_zeros().expect("positive even n-1");
    let odd_part = Zeroizing::new(&*upper >> a);
    let mut bytes = Zeroizing::new(vec![0; n.bits().div_ceil(8)]);
    let mask = 0xff >> ((8 - n.bits() % 8) % 8);
    'round: for _ in 0..rounds {
        let mut base = Zeroizing::new(BigUint::from(0u8));
        let mut sampled = false;
        // Bounded rejection sampling, never reduce modulo n (which biases bases).
        for _ in 0..128 {
            rng.try_fill_bytes(&mut bytes)
                .map_err(|_| RsaPrivateValidationError::RandomnessUnavailable)?;
            bytes[0] &= mask;
            base.zeroize();
            *base = BigUint::from_bytes_be(&bytes);
            if *base > one && *base < *upper {
                sampled = true;
                break;
            }
        }
        if !sampled {
            return Err(RsaPrivateValidationError::RandomnessUnavailable);
        }
        let mut z = Zeroizing::new(base.modpow(&odd_part, n));
        if *z == one || *z == *upper {
            continue;
        }
        for _ in 1..a {
            let square = Zeroizing::new(&*z * &*z);
            z.zeroize();
            *z = &*square % n;
            if *z == *upper {
                continue 'round;
            }
            if *z == one {
                return Ok(false);
            }
        }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::rand_core::{CryptoRng, Error};

    fn key(bits: usize) -> RsaPrivateKey {
        let generated = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).unwrap();
        let mut key = RsaPrivateKey::from_p_q(
            generated.primes()[0].clone(),
            generated.primes()[1].clone(),
            generated.e().clone(),
        )
        .unwrap();
        key.precompute().unwrap();
        key
    }

    #[test]
    fn valid_import_and_noncanonical_private_exponent() {
        let key = key(2048);
        assert_eq!(validate_rsa_private_key(&key, 2048), Ok(()));
        for bits in [0, 1024, 3072, usize::MAX] {
            assert_eq!(
                validate_rsa_private_key(&key, bits),
                Err(RsaPrivateValidationError::InvalidPrivateKey)
            );
        }
        let lambda = (key.primes()[0].clone() - 1u8).lcm(&(key.primes()[1].clone() - 1u8));
        let equivalent = RsaPrivateKey::from_components(
            key.n().clone(),
            key.e().clone(),
            key.d() + lambda,
            key.primes().to_vec(),
        )
        .unwrap();
        // This key works algebraically, but violates the specified range for d.
        equivalent.validate().unwrap();
        assert_eq!(
            validate_rsa_private_key(&equivalent, 2048),
            Err(RsaPrivateValidationError::InvalidPrivateKey)
        );
    }

    #[test]
    fn algebraic_consistency_does_not_prove_factor_primality() {
        let valid = key(2048);
        // 2^1024-1 has small factors, but is large, odd and well separated
        // from the other factor. The ordinary RSA constructor accepts it.
        let composite = (BigUint::from(1u8) << 1024) - 1u8;
        let mut bad =
            RsaPrivateKey::from_p_q(composite, valid.primes()[1].clone(), valid.e().clone())
                .unwrap();
        bad.precompute().unwrap();
        bad.validate().unwrap();
        assert_eq!(
            validate_rsa_private_key(&bad, 2048),
            Err(RsaPrivateValidationError::InvalidPrivateKey)
        );
    }

    #[test]
    fn composite_factors_and_prime_powers_are_rejected() {
        for n in [9u32, 15, 25, 341, 561, 1105, 1729, 3215031751] {
            assert!(!probable_prime(&BigUint::from(n), 57, &mut rsa::rand_core::OsRng).unwrap());
        }
        for n in [3u32, 5, 751, 65537] {
            assert!(probable_prime(&BigUint::from(n), 57, &mut rsa::rand_core::OsRng).unwrap());
        }
    }

    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(0);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}

    #[test]
    fn unusable_randomness_fails_closed() {
        assert_eq!(
            probable_prime(&BigUint::from(65537u32), 57, &mut ZeroRng),
            Err(RsaPrivateValidationError::RandomnessUnavailable)
        );
    }

    // Explicit opt-in timing harness; no hardware, persistence or real keys.
    #[test]
    #[ignore = "RSA import validation timing"]
    fn validation_cost() {
        for bits in [2048, 3072, 4096] {
            let key = key(bits);
            for _ in 0..3 {
                let start = std::time::Instant::now();
                validate_rsa_private_key(&key, bits).unwrap();
                println!("private RSA-{bits} validation: {:?}", start.elapsed());
                let start = std::time::Instant::now();
                crate::rsa_public_validation::validate_rsa_public_key(
                    &key.n().to_bytes_be(),
                    &key.e().to_bytes_be(),
                    bits,
                )
                .unwrap();
                println!("public RSA-{bits} validation: {:?}", start.elapsed());
            }
        }
    }
}
