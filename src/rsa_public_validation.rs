//! RSA public-only plausibility checks from SP 800-89 §5.3.3, referenced by
//! SP 800-56B Rev. 2 §6.4.2.2. This is partial validation, not proof of correct
//! key generation, private-key possession, or FIPS module certification.

use num_integer::Integer;
use rsa::{BigUint, rand_core::RngCore};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPublicValidationError {
    InvalidPublicKey,
    RandomnessUnavailable,
}

// As in OpenSSL's public-key check, five enhanced Miller–Rabin rounds bound
// work on primes/pseudoprimes. Acceptance requires an explicit compositeness /
// non-prime-power witness; passing probable-prime rounds never accepts a key.
const MAX_ROUNDS: usize = 5;
const MAX_BASE_ATTEMPTS: usize = 128;

/// Check a public RSA modulus and exponent before accepting a public-only key.
///
/// The caller supplies the intended modulus size and retains acceptance policy.
/// Cheap size, exponent, oddness and small-factor checks precede the bounded
/// full-modulus enhanced Miller–Rabin test (FIPS 186-5 §B.3.2).
/// Public values only: this routine does not consume private factors or keys.
pub fn validate_rsa_public_key(
    modulus: &[u8],
    exponent: &[u8],
    expected_bits: usize,
) -> Result<(), RsaPublicValidationError> {
    validate_with_rng(modulus, exponent, expected_bits, &mut rsa::rand_core::OsRng)
}

fn validate_with_rng(
    modulus: &[u8],
    exponent: &[u8],
    expected_bits: usize,
    rng: &mut impl RngCore,
) -> Result<(), RsaPublicValidationError> {
    use RsaPublicValidationError::InvalidPublicKey;
    if crate::rsa_private_validation::validation_strength(expected_bits).is_none()
        || modulus.len() != expected_bits.div_ceil(8)
        || modulus.last().is_none_or(|byte| byte & 1 == 0)
        || exponent.is_empty()
        || exponent.len() > 32
    {
        return Err(InvalidPublicKey);
    }
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    // Mathematical validity is separate from NIST size/exponent acceptance.
    if n.bits() != expected_bits
        || e < BigUint::from(3u8)
        || e >= n
        || e.bits() > 256
        || e.is_even()
    {
        return Err(InvalidPublicKey);
    }
    if n.gcd(small_factors()) != BigUint::from(1u8) {
        return Err(InvalidPublicKey);
    }
    let upper = &n - 1u8;
    let a = upper
        .trailing_zeros()
        .expect("nonzero odd modulus minus one");
    let m = &upper >> a;
    for _ in 0..MAX_ROUNDS {
        let b = random_base(&n, rng)?;
        match enhanced_round(&n, &upper, a, &m, &b) {
            Round::CompositeNotPrimePower => return Ok(()),
            Round::CompositeWithFactor => return Err(InvalidPublicKey),
            Round::ProbablyPrime => {}
        }
    }
    Err(InvalidPublicKey)
}

fn small_factors() -> &'static BigUint {
    static FACTORS: OnceLock<BigUint> = OnceLock::new();
    FACTORS.get_or_init(|| {
        // Product of the 132 odd primes 3..=751, SP 800-89 §5.3.3(f).
        let mut product = BigUint::from(1u8);
        for candidate in (3u32..752).step_by(2) {
            if (3..candidate)
                .step_by(2)
                .all(|divisor| candidate % divisor != 0)
            {
                product *= candidate;
            }
        }
        product
    })
}

fn random_base(n: &BigUint, rng: &mut impl RngCore) -> Result<BigUint, RsaPublicValidationError> {
    let mut bytes = vec![0; n.bits().div_ceil(8)];
    let mask = 0xff >> ((8 - n.bits() % 8) % 8);
    let upper = n - 1u8;
    for _ in 0..MAX_BASE_ATTEMPTS {
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| RsaPublicValidationError::RandomnessUnavailable)?;
        bytes[0] &= mask;
        let b = BigUint::from_bytes_be(&bytes);
        if b > BigUint::from(1u8) && b < upper {
            return Ok(b);
        }
    }
    Err(RsaPublicValidationError::RandomnessUnavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Round {
    ProbablyPrime,
    CompositeWithFactor,
    CompositeNotPrimePower,
}

fn enhanced_round(n: &BigUint, upper: &BigUint, a: usize, m: &BigUint, b: &BigUint) -> Round {
    // FIPS 186-5 §B.3.2, steps 4.3–4.14. We do not expose discovered factors.
    let one = BigUint::from(1u8);
    if b.gcd(n) > one {
        return Round::CompositeWithFactor;
    }
    let mut z = b.modpow(m, n);
    if z == one || &z == upper {
        return Round::ProbablyPrime;
    }
    let mut x;
    for _ in 1..a {
        x = z;
        z = (&x * &x) % n;
        if &z == upper {
            return Round::ProbablyPrime;
        }
        if z == one {
            return classify_composite(n, &x);
        }
    }
    x = z;
    z = (&x * &x) % n;
    if z != one {
        x = z;
    }
    classify_composite(n, &x)
}

fn classify_composite(n: &BigUint, x: &BigUint) -> Round {
    if (x - 1u8).gcd(n) > BigUint::from(1u8) {
        Round::CompositeWithFactor
    } else {
        Round::CompositeNotPrimePower
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn public_modulus(encoded: &[u8]) -> Vec<u8> {
        let mut json = String::new();
        GzDecoder::new(encoded).read_to_string(&mut json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        BigUint::parse_bytes(
            value["testGroups"][0]["publicKey"]["modulus"]
                .as_str()
                .unwrap()
                .as_bytes(),
            16,
        )
        .unwrap()
        .to_bytes_be()
    }

    #[test]
    fn published_rsa_moduli_of_every_supported_size_are_accepted() {
        for (bits, encoded) in [
            (
                2048,
                include_bytes!(
                    "../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json.gz"
                )
                .as_slice(),
            ),
            (
                3072,
                include_bytes!(
                    "../tests/vectors/wycheproof/rsa_signature_3072_sha384_test.json.gz"
                )
                .as_slice(),
            ),
            (
                4096,
                include_bytes!(
                    "../tests/vectors/wycheproof/rsa_signature_4096_sha512_test.json.gz"
                )
                .as_slice(),
            ),
        ] {
            assert_eq!(
                validate_rsa_public_key(&public_modulus(encoded), &[1, 0, 1], bits),
                Ok(())
            );
        }
    }

    #[test]
    fn malformed_sizes_exponents_and_small_factors_are_rejected() {
        let n = public_modulus(include_bytes!(
            "../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json.gz"
        ));
        for e in [
            &[][..],
            &[1][..],
            &[0, 1, 0][..],
            &[1, 0, 0][..],
            &[1; 33][..],
        ] {
            assert_eq!(
                validate_rsa_public_key(&n, e, 2048),
                Err(RsaPublicValidationError::InvalidPublicKey)
            );
        }
        for bits in [0, 1024, 2047, 3072, 8192, usize::MAX] {
            assert_eq!(
                validate_rsa_public_key(&n, &[1, 0, 1], bits),
                Err(RsaPublicValidationError::InvalidPublicKey)
            );
        }
        for prime in [2u32, 3, 17, 751] {
            let q = (BigUint::from(1u8) << 2047) / prime + 1u8;
            let bad = q * prime;
            assert_eq!(
                validate_rsa_public_key(&bad.to_bytes_be(), &[1, 0, 1], 2048),
                Err(RsaPublicValidationError::InvalidPublicKey)
            );
        }
    }

    // RFC 3526 §3 group-14 prime. Valid DH parameter, invalid RSA modulus.
    fn group14_prime() -> BigUint {
        BigUint::parse_bytes(
            concat!(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
                "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
                "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
                "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
                "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
                "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
            )
            .as_bytes(),
            16,
        )
        .unwrap()
    }

    #[test]
    fn prime_and_prime_power_moduli_are_rejected() {
        let prime = group14_prime();
        assert_eq!(prime.bits(), 2048);
        assert_eq!(
            validate_rsa_public_key(&prime.to_bytes_be(), &[1, 0, 1], 2048),
            Err(RsaPublicValidationError::InvalidPublicKey)
        );
        let square = &prime * &prime;
        assert_eq!(square.bits(), 4096);
        assert_eq!(
            validate_rsa_public_key(&square.to_bytes_be(), &[1, 0, 1], 4096),
            Err(RsaPublicValidationError::InvalidPublicKey)
        );
    }

    #[test]
    fn enhanced_witness_never_accepts_a_prime_power() {
        for p in [3u32, 5, 7, 11, 757] {
            for exponent in 1..=5 {
                let n = (0..exponent).fold(BigUint::from(1u8), |n, _| n * p);
                let upper = &n - 1u8;
                let a = upper.trailing_zeros().unwrap();
                let m = &upper >> a;
                for b in 2..u32::min(p, 40) {
                    assert_ne!(
                        enhanced_round(&n, &upper, a, &m, &BigUint::from(b)),
                        Round::CompositeNotPrimePower
                    );
                }
            }
        }
    }

    #[test]
    fn unusable_randomness_fails_closed_after_bounded_sampling() {
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
            fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
                bytes.fill(0);
                Ok(())
            }
        }
        let n = public_modulus(include_bytes!(
            "../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json.gz"
        ));
        assert_eq!(
            validate_with_rng(&n, &[1, 0, 1], 2048, &mut ZeroRng),
            Err(RsaPublicValidationError::RandomnessUnavailable)
        );
    }

    #[test]
    fn small_factor_product_covers_every_prime_below_752() {
        for p in [3u32, 5, 727, 733, 739, 743, 751] {
            assert_eq!(small_factors() % p, BigUint::from(0u8));
        }
        assert_ne!(small_factors() % 757u32, BigUint::from(0u8));
    }
}
