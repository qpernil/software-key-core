//! Matched-seed before/after microbenchmark. It never accesses hardware.
use rand::{SeedableRng, rngs::StdRng};
use rsa::{
    BoxedUint, PrivateKey, PublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use software_key_core::rsa_keys::{RsaKey, import_public};
use std::time::Instant;

fn integer(value: &BoxedUint) -> num_bigint_dig::BigUint {
    let bytes = zeroize::Zeroizing::new(value.to_be_bytes());
    num_bigint_dig::BigUint::from_bytes_be(&bytes)
}

fn timed<T>(operation: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let result = operation();
    (result, start.elapsed().as_secs_f64())
}
fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .map(|value| value.parse().expect("RSA bits"))
        .collect();
    let sizes = if sizes.is_empty() {
        vec![1024, 1280, 2048, 2304, 3072, 4096]
    } else {
        sizes
    };
    for bits in sizes {
        for sample in 1..=3 {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).unwrap();
            let mut before_rng = StdRng::from_seed(seed);
            let mut after_rng = StdRng::from_seed(seed);
            let (before, before_generate) = timed(|| {
                let mut key = PrivateKey::new(&mut before_rng, bits).unwrap();
                key.precompute().unwrap();
                key
            });
            let (after, after_generate) =
                timed(|| RsaKey::generate_with_rng(&mut after_rng, bits).unwrap());
            assert_eq!(
                before.n(),
                after.n(),
                "generation must use identical candidate streams"
            );
            let (_, before_private) = timed(|| {
                let mut key = PrivateKey::from_p_q(
                    before.primes()[0].as_ref().clone(),
                    before.primes()[1].as_ref().clone(),
                    before.e().clone(),
                )
                .unwrap();
                key.precompute().unwrap();
                key
            });
            let (_, after_private) = timed(|| {
                RsaKey::import_primes(
                    integer(&before.primes()[0]),
                    integer(&before.primes()[1]),
                    integer(before.e()),
                )
                .unwrap()
            });
            let (_, before_public) =
                timed(|| PublicKey::new(before.n().as_ref().clone(), before.e().clone()).unwrap());
            let (_, after_public) =
                timed(|| import_public(integer(before.n()), integer(before.e())).unwrap());
            // A private-operation comparison outside construction/validation.
            let input = BoxedUint::from_be_slice(&[42], before.n().bits_precision()).unwrap();
            let (_, before_operations) = timed(|| {
                for _ in 0..20 {
                    rsa::hazmat::rsa_decrypt_and_check(
                        &before,
                        Some(&mut getrandom::SysRng),
                        &input,
                    )
                    .unwrap();
                }
            });
            let (_, after_operations) = timed(|| {
                for _ in 0..20 {
                    rsa::hazmat::rsa_decrypt_and_check(
                        after.as_ref(),
                        Some(&mut getrandom::SysRng),
                        &input,
                    )
                    .unwrap();
                }
            });
            println!(
                "{}",
                serde_json::json!({"bits":bits,"sample":sample,
                "generate":{"before":before_generate,"after":after_generate},
                "private_import":{"before":before_private,"after":after_private},
                "public_import":{"before":before_public,"after":after_public},
                "private_operation":{"before":before_operations/20.0,"after":after_operations/20.0}})
            );
        }
    }
}
