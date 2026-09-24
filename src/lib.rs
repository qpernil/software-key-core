//! Protocol-neutral software key operations and opt-in durable-state mechanics.
//!
//! This crate provides reusable key generation, signing, verification, and key
//! agreement without depending on a device protocol or provider API. The optional
//! `state-persistence` feature provides Unix state-file locking, atomic writes,
//! and batched or immediate durable mutation scheduling. The optional
//! `x509-signing` feature provides standard SubjectPublicKeyInfo projection and
//! certificate signing for software keys. The `x509-validation` feature provides
//! certificate parsing and explicit-anchor chain validation. Protocol and provider
//! layers retain responsibility for identifiers, certificate profiles and
//! extensions, authorization policy, state formats, lifecycle, and error mapping.

pub mod arkg;
pub mod brainpool512;
#[cfg(feature = "x509-validation")]
pub mod certificate_chain;
#[cfg(feature = "x509-signing")]
pub mod certificate_signing;
pub mod counter_kdf;
pub mod digest;
pub mod post_quantum;
pub mod rsa_signing;
pub mod secure_channel;
pub mod software_key_agreement;
pub mod software_private_key;
pub mod software_signing;
pub mod software_symmetric;
#[cfg(all(unix, feature = "state-persistence"))]
pub mod state_persistence;

#[cfg(test)]
mod zeroization_tests {
    use super::{
        post_quantum::{MlDsaPrivateKey, MlKemPrivateKey},
        software_key_agreement::SoftwareMontgomeryKey,
        software_private_key::SoftwarePrivateKey,
        software_signing::SoftwareSigningKey,
    };
    use zeroize::ZeroizeOnDrop;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn every_typed_private_key_wrapper_guarantees_zeroization_on_drop() {
        assert_zeroize_on_drop::<SoftwareSigningKey>();
        assert_zeroize_on_drop::<SoftwareMontgomeryKey>();
        assert_zeroize_on_drop::<MlDsaPrivateKey>();
        assert_zeroize_on_drop::<MlKemPrivateKey>();
        assert_zeroize_on_drop::<SoftwarePrivateKey>();
    }
}
