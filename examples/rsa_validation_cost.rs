//! Matched-seed before/after microbenchmark. It never accesses hardware.
use rand::{SeedableRng, rngs::StdRng};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    rand_core::RngCore,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use software_key_core::rsa_keys::{RsaKey, import_public};
use std::time::Instant;

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
            rsa::rand_core::OsRng.fill_bytes(&mut seed);
            let mut before_rng = StdRng::from_seed(seed);
            let mut after_rng = StdRng::from_seed(seed);
            let (before, before_generate) = timed(|| {
                let mut key = RsaPrivateKey::new(&mut before_rng, bits).unwrap();
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
                let mut key = RsaPrivateKey::from_p_q(
                    before.primes()[0].clone(),
                    before.primes()[1].clone(),
                    before.e().clone(),
                )
                .unwrap();
                key.precompute().unwrap();
                key
            });
            let (_, after_private) = timed(|| {
                RsaKey::import_primes(
                    before.primes()[0].clone(),
                    before.primes()[1].clone(),
                    before.e().clone(),
                )
                .unwrap()
            });
            let (_, before_public) =
                timed(|| RsaPublicKey::new(before.n().clone(), before.e().clone()).unwrap());
            let (_, after_public) =
                timed(|| import_public(before.n().clone(), before.e().clone()).unwrap());
            // A private-operation comparison outside construction/validation.
            let input = BigUint::from(42u8);
            let (_, before_operations) = timed(|| {
                for _ in 0..20 {
                    rsa::hazmat::rsa_decrypt_and_check(
                        &before,
                        Some(&mut rsa::rand_core::OsRng),
                        &input,
                    )
                    .unwrap();
                }
            });
            let (_, after_operations) = timed(|| {
                for _ in 0..20 {
                    rsa::hazmat::rsa_decrypt_and_check(
                        after.as_ref(),
                        Some(&mut rsa::rand_core::OsRng),
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
