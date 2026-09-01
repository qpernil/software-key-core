//! Constant-time brainpoolP512r1 private-key arithmetic.

use elliptic_curve::{
    CurveArithmetic, PrimeCurve, PrimeCurveArithmetic,
    array::typenum::{U64, U1024},
    bigint::{Odd, U512},
    hazmat::FieldArithmetic,
};
use primeorder::{PrimeCurveParams, mul_backend, point_arithmetic};

const ORDER_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
const ORDER: Odd<U512> = Odd::<U512>::from_be_hex(ORDER_HEX);

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP512r1;

impl elliptic_curve::Curve for BrainpoolP512r1 {
    type FieldBytesSize = U64;
    type Uint = U512;

    const ORDER: Odd<U512> = ORDER;
}

impl PrimeCurve for BrainpoolP512r1 {}

impl elliptic_curve::pkcs8::AssociatedOid for BrainpoolP512r1 {
    const OID: elliptic_curve::pkcs8::ObjectIdentifier =
        elliptic_curve::pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13");
}

impl elliptic_curve::point::PointCompression for BrainpoolP512r1 {
    const COMPRESS_POINTS: bool = false;
}

pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP512r1>;
pub type Signature = ecdsa::Signature<BrainpoolP512r1>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrainpoolP512VerifyError;

impl core::fmt::Display for BrainpoolP512VerifyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("invalid BrainpoolP512r1 public key or signature")
    }
}

impl std::error::Error for BrainpoolP512VerifyError {}

mod field {
    use super::U512;
    use elliptic_curve::{
        ff::PrimeField,
        subtle::{Choice, ConstantTimeEq, CtOption},
    };

    primefield::monty_field_params! {
        name: FieldParams,
        modulus: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        uint: U512,
        byte_order: primefield::ByteOrder::BigEndian,
        multiplicative_generator: 2,
        doc: "Montgomery parameters for the brainpoolP512r1 base field"
    }

    primefield::monty_field_element! {
        name: FieldElement,
        params: FieldParams,
        uint: U512,
        doc: "Element in the brainpoolP512r1 base field"
    }

    primefield::monty_field_arithmetic! {
        name: FieldElement,
        params: FieldParams,
        uint: U512
    }

    impl elliptic_curve::ops::BatchInvert for FieldElement {}
}

mod scalar {
    use super::{BrainpoolP512r1, ORDER, ORDER_HEX, U512, U1024};
    use elliptic_curve::{
        ff::PrimeField,
        scalar::{FromUintUnchecked, IsHigh},
        subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
    };

    primefield::monty_field_params! {
        name: ScalarParams,
        modulus: ORDER_HEX,
        uint: U512,
        byte_order: primefield::ByteOrder::BigEndian,
        multiplicative_generator: 7,
        doc: "Montgomery parameters for the brainpoolP512r1 scalar field"
    }

    primefield::monty_field_element! {
        name: Scalar,
        params: ScalarParams,
        uint: U512,
        doc: "Element in the brainpoolP512r1 scalar field"
    }

    primefield::monty_field_arithmetic! {
        name: Scalar,
        params: ScalarParams,
        uint: U512
    }

    primefield::monty_field_reduce! {
        name: Scalar,
        params: ScalarParams,
        uint: U512,
    }

    elliptic_curve::scalar_impls!(BrainpoolP512r1, Scalar);

    impl primeorder::wnaf::WnafSize for Scalar {
        type StorageSize = U1024;
    }

    impl AsRef<Scalar> for Scalar {
        fn as_ref(&self) -> &Scalar {
            self
        }
    }

    impl FromUintUnchecked for Scalar {
        type Uint = U512;

        fn from_uint_unchecked(uint: Self::Uint) -> Self {
            Self::from_uint_unchecked(uint)
        }
    }

    impl IsHigh for Scalar {
        fn is_high(&self) -> Choice {
            const MODULUS_SHR1: U512 = ORDER.as_ref().shr_vartime(1);
            self.to_canonical().ct_gt(&MODULUS_SHR1)
        }
    }
}

use field::FieldElement;
use scalar::Scalar;

pub type AffinePoint = primeorder::AffinePoint<BrainpoolP512r1>;
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP512r1>;

impl CurveArithmetic for BrainpoolP512r1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl FieldArithmetic for BrainpoolP512r1 {
    type FieldElement = FieldElement;
}

impl PrimeCurveArithmetic for BrainpoolP512r1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP512r1 {
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;
    type Backend = mul_backend::VariableOnly;

    const EQUATION_A: FieldElement = FieldElement::from_hex_vartime(
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    );
    const EQUATION_B: FieldElement = FieldElement::from_hex_vartime(
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    );
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex_vartime(
            "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        ),
        FieldElement::from_hex_vartime(
            "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        ),
    );
}

impl ecdsa::EcdsaCurve for BrainpoolP512r1 {
    const NORMALIZE_S: bool = false;
}

impl ecdsa::DigestAlgorithm for BrainpoolP512r1 {
    type Digest = sha2::Sha512;
}

/// Verify a BrainpoolP512r1 signature over a caller-supplied digest.
///
/// The arithmetic here only processes public values. It intentionally avoids
/// RustCrypto's wNAF multi-scalar verifier because `hybrid-array` does not
/// provide the 513-entry array size required by a 512-bit scalar field.
pub fn verify_prehash(
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), BrainpoolP512VerifyError> {
    use num_bigint_dig::traits::ModInverse;
    use rsa::BigUint;

    const COORDINATE_LENGTH: usize = 64;
    if public_key.len() != 1 + 2 * COORDINATE_LENGTH
        || public_key[0] != 0x04
        || signature.len() != 2 * COORDINATE_LENGTH
    {
        return Err(BrainpoolP512VerifyError);
    }
    let p = biguint(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
    )?;
    let a = biguint(
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    )?;
    let b = biguint(
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    )?;
    let n = biguint(ORDER_HEX)?;
    let generator = PublicPoint {
        x: biguint(
            "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        )?,
        y: biguint(
            "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        )?,
        z: BigUint::from(1_u8),
    };
    let public = PublicPoint {
        x: BigUint::from_bytes_be(&public_key[1..65]),
        y: BigUint::from_bytes_be(&public_key[65..]),
        z: BigUint::from(1_u8),
    };
    if public.x >= p || public.y >= p {
        return Err(BrainpoolP512VerifyError);
    }
    let lhs = (&public.y * &public.y) % &p;
    let rhs = (((&public.x * &public.x * &public.x) + (&a * &public.x)) + &b) % &p;
    if lhs != rhs {
        return Err(BrainpoolP512VerifyError);
    }
    let r = BigUint::from_bytes_be(&signature[..COORDINATE_LENGTH]);
    let s = BigUint::from_bytes_be(&signature[COORDINATE_LENGTH..]);
    let zero = BigUint::from(0_u8);
    if r == zero || r >= n || s == zero || s >= n {
        return Err(BrainpoolP512VerifyError);
    }
    let mut z = BigUint::from_bytes_be(digest);
    if digest.len() * 8 > n.bits() {
        z >>= digest.len() * 8 - n.bits();
    }
    let w = s
        .mod_inverse(&n)
        .and_then(|value| value.to_biguint())
        .ok_or(BrainpoolP512VerifyError)?;
    let point = multiply_sum(
        &((z * &w) % &n),
        &generator,
        &((&r * &w) % &n),
        &public,
        &p,
        &a,
    );
    if point.z == zero {
        return Err(BrainpoolP512VerifyError);
    }
    let inverse = point
        .z
        .mod_inverse(&p)
        .and_then(|value| value.to_biguint())
        .ok_or(BrainpoolP512VerifyError)?;
    let x = (&point.x * &inverse * &inverse) % &p;
    (x % n == r).then_some(()).ok_or(BrainpoolP512VerifyError)
}

#[derive(Clone)]
struct PublicPoint {
    x: rsa::BigUint,
    y: rsa::BigUint,
    z: rsa::BigUint,
}

fn biguint(value: &str) -> Result<rsa::BigUint, BrainpoolP512VerifyError> {
    rsa::BigUint::parse_bytes(value.as_bytes(), 16).ok_or(BrainpoolP512VerifyError)
}

fn mod_sub(left: &rsa::BigUint, right: &rsa::BigUint, modulus: &rsa::BigUint) -> rsa::BigUint {
    if left >= right {
        (left - right) % modulus
    } else {
        modulus - ((right - left) % modulus)
    }
}

fn double(point: &PublicPoint, p: &rsa::BigUint, a: &rsa::BigUint) -> PublicPoint {
    let zero = rsa::BigUint::from(0_u8);
    if point.z == zero || point.y == zero {
        return PublicPoint {
            x: zero.clone(),
            y: rsa::BigUint::from(1_u8),
            z: zero,
        };
    }
    let xx = (&point.x * &point.x) % p;
    let yy = (&point.y * &point.y) % p;
    let yyyy = (&yy * &yy) % p;
    let zz = (&point.z * &point.z) % p;
    let x_plus_yy = (&point.x + &yy) % p;
    let mut s = mod_sub(&((&x_plus_yy * &x_plus_yy) % p), &xx, p);
    s = mod_sub(&s, &yyyy, p);
    s = (&s * rsa::BigUint::from(2_u8)) % p;
    let m = ((&xx * rsa::BigUint::from(3_u8)) + (a * &zz * &zz)) % p;
    let x = mod_sub(&((&m * &m) % p), &((&s * rsa::BigUint::from(2_u8)) % p), p);
    let mut y = (&m * mod_sub(&s, &x, p)) % p;
    y = mod_sub(&y, &((&yyyy * rsa::BigUint::from(8_u8)) % p), p);
    let z = ((&point.y * &point.z) * rsa::BigUint::from(2_u8)) % p;
    PublicPoint { x, y, z }
}

fn add(left: &PublicPoint, right: &PublicPoint, p: &rsa::BigUint, a: &rsa::BigUint) -> PublicPoint {
    let zero = rsa::BigUint::from(0_u8);
    if left.z == zero {
        return right.clone();
    }
    if right.z == zero {
        return left.clone();
    }
    let z1z1 = (&left.z * &left.z) % p;
    let z2z2 = (&right.z * &right.z) % p;
    let u1 = (&left.x * &z2z2) % p;
    let u2 = (&right.x * &z1z1) % p;
    let s1 = ((&left.y * &right.z) * &z2z2) % p;
    let s2 = ((&right.y * &left.z) * &z1z1) % p;
    if u1 == u2 {
        return if s1 == s2 {
            double(left, p, a)
        } else {
            PublicPoint {
                x: zero.clone(),
                y: rsa::BigUint::from(1_u8),
                z: zero,
            }
        };
    }
    let h = mod_sub(&u2, &u1, p);
    let two_h = (&h * rsa::BigUint::from(2_u8)) % p;
    let i = (&two_h * &two_h) % p;
    let j = (&h * &i) % p;
    let r = (mod_sub(&s2, &s1, p) * rsa::BigUint::from(2_u8)) % p;
    let v = (&u1 * &i) % p;
    let mut x = mod_sub(&((&r * &r) % p), &j, p);
    x = mod_sub(&x, &((&v * rsa::BigUint::from(2_u8)) % p), p);
    let mut y = (&r * mod_sub(&v, &x, p)) % p;
    y = mod_sub(&y, &(((&s1 * &j) * rsa::BigUint::from(2_u8)) % p), p);
    let z_sum = (&left.z + &right.z) % p;
    let mut z = mod_sub(&((&z_sum * &z_sum) % p), &z1z1, p);
    z = mod_sub(&z, &z2z2, p);
    z = (&z * &h) % p;
    PublicPoint { x, y, z }
}

fn multiply_sum(
    left_scalar: &rsa::BigUint,
    left: &PublicPoint,
    right_scalar: &rsa::BigUint,
    right: &PublicPoint,
    p: &rsa::BigUint,
    a: &rsa::BigUint,
) -> PublicPoint {
    let left_bytes = left_scalar.to_bytes_be();
    let right_bytes = right_scalar.to_bytes_be();
    let length = left_bytes.len().max(right_bytes.len());
    let combined = add(left, right, p, a);
    let mut result = PublicPoint {
        x: rsa::BigUint::from(0_u8),
        y: rsa::BigUint::from(1_u8),
        z: rsa::BigUint::from(0_u8),
    };
    let left_offset = length - left_bytes.len();
    let right_offset = length - right_bytes.len();
    for index in 0..length {
        let left_byte = if index < left_offset {
            0
        } else {
            left_bytes[index - left_offset]
        };
        let right_byte = if index < right_offset {
            0
        } else {
            right_bytes[index - right_offset]
        };
        for bit in (0..8).rev() {
            result = double(&result, p, a);
            result = match (left_byte & (1 << bit) != 0, right_byte & (1 << bit) != 0) {
                (false, false) => result,
                (true, false) => add(&result, left, p, a),
                (false, true) => add(&result, right, p, a),
                (true, true) => add(&result, &combined, p, a),
            };
        }
    }
    result
}
