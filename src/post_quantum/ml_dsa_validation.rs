//! Application-side expanded-key validation using the public ML-DSA parameter API.
//!
//! The dependency's deprecated expanded decoder assumes well-formed input. Check
//! encodings and the FIPS 204 Algorithm 6 relation before decoding or signing.

use ml_dsa::{ExpandedSigningKeyBytes, MlDsaParams, common::typenum::Unsigned};
use module_lattice::{Elem, Field};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::MlDsaError;

const Q: u32 = 8_380_417;

// FIPS 204 Appendix B: zeta^{BitRev8(i)}, with unused entry 0 left as zero.
const ZETAS: [u32; 256] = {
    let mut powers = [0u32; 256];
    let mut power = 1u64;
    let mut i = 0;
    while i < 256 {
        powers[i] = power as u32;
        power = power * 1753 % Q as u64;
        i += 1;
    }
    let mut zetas = [0; 256];
    i = 1;
    while i < 256 {
        zetas[i] = powers[(i as u8).reverse_bits() as usize];
        i += 1;
    }
    zetas
};

// FIPS 204 Algorithms 41/42. Field operations use module-lattice's existing
// branchless reductions; only public loop counters select twiddles and indices.
fn ntt<F: Field<Int = u32>>(values: &mut [Elem<F>], inverse: bool) {
    let mut twiddle = if inverse { 256 } else { 0 };
    for layer in 0..8 {
        let length = 1 << if inverse { layer } else { 7 - layer };
        for start in (0..256).step_by(2 * length) {
            let zeta = if inverse {
                twiddle -= 1;
                -Elem::new(ZETAS[twiddle])
            } else {
                twiddle += 1;
                Elem::new(ZETAS[twiddle])
            };
            for i in start..start + length {
                let left = values[i];
                if inverse {
                    values[i] = left + values[i + length];
                    values[i + length] = zeta * (left - values[i + length]);
                } else {
                    let right = zeta * values[i + length];
                    values[i] = left + right;
                    values[i + length] = left - right;
                }
            }
        }
    }
    if inverse {
        for value in values {
            *value = Elem::new(8_347_681) * *value; // 256^{-1} mod q
        }
    }
}

fn valid_small_secret_encoding(encoded: &[u8], eta: u32) -> bool {
    let width = (2 * eta).ilog2() + 1;
    let mask = (1u32 << width) - 1;
    let mut accumulator = 0u32;
    let mut available = 0;
    let mut valid = true;
    for byte in encoded {
        accumulator |= u32::from(*byte) << available;
        available += 8;
        while available >= width {
            valid &= accumulator & mask <= 2 * eta;
            accumulator >>= width;
            available -= width;
        }
    }
    valid
}

// Keep validation vectors out of the dependency decoder's construction frame.
#[inline(never)]
pub(super) fn validate<P: MlDsaParams>(
    encoded: &ExpandedSigningKeyBytes<P>,
) -> Result<(), MlDsaError> {
    let (rho, _, _, s1, s2, t0) = P::split_sk(encoded);
    if !valid_small_secret_encoding(s1, P::Eta::U32)
        || !valid_small_secret_encoding(s2, P::Eta::U32)
    {
        return Err(MlDsaError::InvalidExpandedPrivateKey);
    }
    let mut s1_hat = Zeroizing::new(P::decode_s1(s1));
    for polynomial in s1_hat.0.iter_mut() {
        ntt(&mut polynomial.0, false);
    }
    let mut t = Zeroizing::new(P::decode_s2(s2));
    for (row_index, row) in t.0.iter_mut().enumerate() {
        let mut product = Zeroizing::new(row.0);
        product.fill(Elem::new(0));
        for (column_index, column) in s1_hat.0.iter().enumerate() {
            // ExpandA (Algorithms 30/32): the public matrix is sampled directly
            // in NTT form from SHAKE128(rho || column || row).
            let mut shake = Shake128::default();
            shake.update(rho);
            shake.update(&[column_index as u8, row_index as u8]);
            let mut reader = shake.finalize_xof();
            for (accumulator, secret) in product.iter_mut().zip(column.0.iter()) {
                let coefficient = loop {
                    let mut bytes = [0u8; 3];
                    reader.read(&mut bytes);
                    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2] & 0x7f, 0]);
                    if value < Q {
                        break value;
                    }
                };
                *accumulator = *accumulator + Elem::new(coefficient) * *secret;
            }
        }
        ntt(&mut product, true);
        for (coefficient, product) in row.0.iter_mut().zip(product.iter()) {
            let value = *coefficient + *product;
            // Power2Round, Algorithm 35, with d = 13.
            let high = (value.0 + 4095) >> 13;
            *coefficient = value - Elem::new(high << 13);
        }
    }
    let expected_t0 = Zeroizing::new(P::encode_t0(&t));
    if !bool::from(expected_t0.as_slice().ct_eq(t0.as_slice())) {
        return Err(MlDsaError::InvalidExpandedPrivateKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey};

    fn check<P: MlDsaParams>() {
        for seed in [0, 7, 255] {
            let key = SigningKey::<P>::from_seed(&[seed; 32].into());
            #[allow(deprecated)]
            let encoded = Zeroizing::new(key.expanded_key().to_expanded());
            assert!(validate::<P>(&encoded).is_ok());
            let (_, _, _, s1, s2, t0) = P::split_sk(&encoded);
            let s2_start = 128 + s1.len();
            let t0_start = s2_start + s2.len();
            let t0_length = t0.len();
            // Reject inconsistent low bits in each matrix row before signing.
            for row in 0..P::K::USIZE {
                let mut bad = Zeroizing::new(encoded.clone());
                bad[t0_start + row * (t0_length / P::K::USIZE)] ^= 1;
                assert!(validate::<P>(&bad).is_err());
            }
            // Both secret vectors contain packed codes reserved by FIPS 204.
            for offset in [128, s2_start] {
                let mut bad = Zeroizing::new(encoded.clone());
                bad[offset] = 0xff;
                assert!(validate::<P>(&bad).is_err());
            }
        }
    }

    #[test]
    fn expanded_validation_checks_every_parameter_set_and_matrix_row() {
        check::<MlDsa44>();
        check::<MlDsa65>();
        check::<MlDsa87>();
    }
}
