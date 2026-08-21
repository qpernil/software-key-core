//! Protocol-neutral software key operations.
//!
//! This crate provides reusable key generation, signing, verification, and key
//! agreement without depending on a device protocol or provider API. Protocol
//! and provider layers retain responsibility for identifiers, public-key
//! containers, signature encodings, authorization policy, persistence, and
//! error mapping.

pub mod post_quantum;
pub mod rsa_signing;
pub mod software_key_agreement;
pub mod software_signing;
