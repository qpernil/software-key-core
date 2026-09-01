//! Protocol-neutral ownership of parsed software private keys.
//!
//! This type is deliberately limited to runtime key material. Protocol object
//! metadata, persistence records, wire identifiers, and authorization policy
//! remain with callers.

use crate::{
    post_quantum::MlKemPrivateKey, software_key_agreement::SoftwareX25519Key,
    software_signing::SoftwareSigningKey,
};
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// A parsed private key retained by a software-backed runtime object.
#[derive(Clone)]
pub enum SoftwarePrivateKey {
    Signing(SoftwareSigningKey),
    X25519(SoftwareX25519Key),
    MlKem(MlKemPrivateKey),
}

// Every variant owns a typed key whose secret state is cleared on drop.
impl ZeroizeOnDrop for SoftwarePrivateKey {}

impl fmt::Debug for SoftwarePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signing(key) => formatter.debug_tuple("Signing").field(key).finish(),
            Self::X25519(_) => formatter.write_str("X25519([REDACTED])"),
            Self::MlKem(key) => formatter
                .debug_struct("MlKem")
                .field("parameter_set", &key.parameter_set())
                .finish_non_exhaustive(),
        }
    }
}

impl From<SoftwareSigningKey> for SoftwarePrivateKey {
    fn from(key: SoftwareSigningKey) -> Self {
        Self::Signing(key)
    }
}

impl From<SoftwareX25519Key> for SoftwarePrivateKey {
    fn from(key: SoftwareX25519Key) -> Self {
        Self::X25519(key)
    }
}

impl From<MlKemPrivateKey> for SoftwarePrivateKey {
    fn from(key: MlKemPrivateKey) -> Self {
        Self::MlKem(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post_quantum::{MlKemParameterSet, MlKemPrivateKey};

    #[test]
    fn conversions_preserve_the_parsed_key_family() {
        let signing =
            SoftwareSigningKey::generate_for_kind(crate::software_signing::KeyKind::Ed25519)
                .unwrap();
        assert!(matches!(
            SoftwarePrivateKey::from(signing),
            SoftwarePrivateKey::Signing(_)
        ));

        let x25519 = SoftwareX25519Key::generate().unwrap();
        assert!(matches!(
            SoftwarePrivateKey::from(x25519),
            SoftwarePrivateKey::X25519(_)
        ));

        let ml_kem = MlKemPrivateKey::generate(MlKemParameterSet::MlKem512).unwrap();
        assert!(matches!(
            SoftwarePrivateKey::from(ml_kem),
            SoftwarePrivateKey::MlKem(_)
        ));
    }

    #[test]
    fn debug_output_never_contains_private_material() {
        let key = SoftwarePrivateKey::from(SoftwareX25519Key::from_serialized(&[7; 32]).unwrap());
        assert_eq!(format!("{key:?}"), "X25519([REDACTED])");
    }
}
