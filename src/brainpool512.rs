//! Constant-time brainpoolP512r1 private-key arithmetic.

use elliptic_curve::{
    array::typenum::{U1024, U64},
    bigint::{Odd, U512},
    hazmat::FieldArithmetic,
    CurveArithmetic, PrimeCurve, PrimeCurveArithmetic,
};
use primeorder::{mul_backend, point_arithmetic, PrimeCurveParams};

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
    use super::{BrainpoolP512r1, ORDER, ORDER_HEX, U1024, U512};
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
