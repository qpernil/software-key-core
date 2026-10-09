//! Strict DER certificate parsing and explicitly configured X.509 trust.
//!
//! Presented certificates never become trust anchors. Callers own application
//! policy and map validation failures to their protocol's errors.

/// A malformed certificate, invalid trust configuration, or failed chain validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateError;

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate validation failed")
    }
}

impl std::error::Error for CertificateError {}

type Error = CertificateError;
const INVALID: CertificateError = CertificateError;
use crate::software_signing::{EcCurve, SoftwarePublicKey};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode, asn1::ObjectIdentifier as DerObjectIdentifier};
use rustls_pki_types::UnixTime;
use std::collections::HashSet;
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, KeyUsage},
};

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const AUTHORITY_INFORMATION_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

mod portable;

type Fingerprint = [u8; 32];

fn supported_signature_algorithms()
-> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] {
    webpki::ALL_VERIFICATION_ALGS
}

#[derive(Clone)]
pub struct ParsedCertificate {
    certificate: Certificate,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    fingerprint: Fingerprint,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
    can_sign_certificates: bool,
}

impl ParsedCertificate {
    /// The parsed, canonical X.509 certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    pub fn parse(encoded: &[u8]) -> Result<Self, Error> {
        let certificate = Certificate::from_der(encoded).map_err(|_| INVALID)?;
        if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
            return Err(INVALID);
        }
        validate_critical_extensions(&certificate)?;
        // Policy evaluation may legitimately finish with a null policy tree;
        // malformed extension syntax must still fail before path validation.
        let policies = certificate
            .tbs_certificate()
            .get_extension::<x509_cert::ext::pkix::CertificatePolicies>()
            .map_err(|_| INVALID)?;
        if policies.is_some_and(|(_, policies)| policies.0.is_empty()) {
            return Err(INVALID);
        }
        let basic_constraints = certificate
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(|_| INVALID)?
            .map(|(_, constraints)| constraints);
        let key_usage = certificate
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|_| INVALID)?
            .map(|(_, usage)| usage);
        let canonical = certificate.to_der().map_err(|_| INVALID)?;
        if canonical != encoded {
            return Err(INVALID);
        }

        Ok(Self {
            subject: certificate
                .tbs_certificate()
                .subject()
                .to_der()
                .map_err(|_| INVALID)?,
            issuer: certificate
                .tbs_certificate()
                .issuer()
                .to_der()
                .map_err(|_| INVALID)?,
            fingerprint: sha256_fingerprint(&canonical),
            not_before: certificate
                .tbs_certificate()
                .validity()
                .not_before
                .to_unix_duration()
                .as_secs(),
            not_after: certificate
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs(),
            is_ca: basic_constraints
                .as_ref()
                .is_some_and(|constraints| constraints.ca),
            can_sign_certificates: key_usage.as_ref().is_none_or(KeyUsage::key_cert_sign),
            certificate,
        })
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        self.not_before <= timestamp && timestamp <= self.not_after
    }

    pub fn verify_signature(&self, issuer: &Self) -> Result<(), Error> {
        verify_certificate_signature(&self.certificate, &issuer.certificate)
    }

    pub fn p256_public_point(&self) -> Result<Vec<u8>, Error> {
        p256_public_point(&self.certificate)
    }

    /// Require an end-entity key authorized for key agreement.
    pub fn p256_key_agreement_point(&self) -> Result<Vec<u8>, Error> {
        let usage = self
            .certificate
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|_| INVALID)?;
        if self.is_ca || usage.is_some_and(|(_, usage)| !usage.key_agreement()) {
            return Err(INVALID);
        }
        self.p256_public_point()
    }
}

#[derive(Clone)]
pub struct CertificateTrust {
    root_fingerprints: HashSet<Fingerprint>,
    fingerprint: Fingerprint,
    local_certificates: Vec<Vec<u8>>,
}

impl CertificateTrust {
    /// Validate a key-agreement chain against an explicitly provisioned P-256 CA
    /// public key. No presented certificate supplies trust. Names select possible
    /// issuer paths, but every path must terminate at the caller's fixed key.
    /// Unlike certificate-based anchors, a bare key has no validity interval or
    /// name constraints; the provisioning owner supplies that policy.
    pub fn validate_with_p256_ca_key(
        point: &[u8],
        certificates: &[Vec<u8>],
    ) -> Result<Vec<u8>, CertificateError> {
        SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: point.to_vec(),
        }
        .validate()
        .map_err(|_| INVALID)?;
        portable::validate_with_p256_ca_key(point, certificates)?.p256_key_agreement_point()
    }

    pub fn new(certificates: &[Vec<u8>]) -> Result<Self, Error> {
        if certificates.is_empty() {
            return Err(INVALID);
        }
        let local = parse_unique(certificates)?;
        let now = UnixTime::now().as_secs();
        let mut root_fingerprints = HashSet::new();
        for certificate in &local {
            if certificate.is_self_issued() {
                if !certificate.is_ca
                    || !certificate.can_sign_certificates
                    || !certificate.is_valid_at(now)
                    || certificate.verify_signature(certificate).is_err()
                {
                    return Err(INVALID);
                }
                root_fingerprints.insert(certificate.fingerprint);
            }
        }
        if root_fingerprints.is_empty() {
            return Err(INVALID);
        }

        let mut fingerprints = local
            .iter()
            .map(|certificate| certificate.fingerprint)
            .collect::<Vec<_>>();
        fingerprints.sort_unstable();
        let fingerprint = sha256_fingerprint(&fingerprints.concat());
        Ok(Self {
            root_fingerprints,
            fingerprint,
            local_certificates: certificates.to_vec(),
        })
    }

    pub fn validate_p256_public_point(&self, certificates: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        self.validate(certificates)?.p256_public_point()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Validate a leaf-last chain and require a P-256 key-agreement leaf.
    pub fn validate_p256_key_agreement_point(
        &self,
        certificates: &[Vec<u8>],
    ) -> Result<Vec<u8>, Error> {
        self.validate(certificates)?.p256_key_agreement_point()
    }

    fn validate(&self, certificates: &[Vec<u8>]) -> Result<ParsedCertificate, Error> {
        portable::validate(self, certificates)
    }
}

fn parse_unique(certificates: &[Vec<u8>]) -> Result<Vec<ParsedCertificate>, Error> {
    let mut fingerprints = HashSet::new();
    certificates
        .iter()
        .map(|encoded| ParsedCertificate::parse(encoded))
        .filter_map(|result| match result {
            Ok(certificate) if fingerprints.insert(certificate.fingerprint) => {
                Some(Ok(certificate))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn validate_critical_extensions(certificate: &Certificate) -> Result<(), Error> {
    const SUPPORTED: &[ObjectIdentifier] = &[
        SUBJECT_KEY_IDENTIFIER,
        KEY_USAGE,
        SUBJECT_ALT_NAME,
        BASIC_CONSTRAINTS,
        CERTIFICATE_POLICIES,
        EXTENDED_KEY_USAGE,
        AUTHORITY_KEY_IDENTIFIER,
        CRL_DISTRIBUTION_POINTS,
        AUTHORITY_INFORMATION_ACCESS,
        ObjectIdentifier::new_unwrap("2.5.29.30"), // nameConstraints
        ObjectIdentifier::new_unwrap("2.5.29.33"), // policyMappings
        ObjectIdentifier::new_unwrap("2.5.29.36"), // policyConstraints
        ObjectIdentifier::new_unwrap("2.5.29.54"), // inhibitAnyPolicy
    ];
    if certificate
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .any(|extension| extension.critical && !SUPPORTED.contains(&extension.extn_id))
    {
        Err(INVALID)
    } else {
        Ok(())
    }
}

fn algorithm_parameter_oid(
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<DerObjectIdentifier, Error> {
    spki.algorithm
        .parameters
        .as_ref()
        .ok_or(INVALID)?
        .decode_as::<DerObjectIdentifier>()
        .map_err(|_| INVALID)
}

fn algorithm_identifier_contents(
    algorithm: &spki::AlgorithmIdentifierOwned,
) -> Result<Vec<u8>, Error> {
    let mut encoded = algorithm.oid.to_der().map_err(|_| INVALID)?;
    if let Some(parameters) = &algorithm.parameters {
        encoded.extend(parameters.to_der().map_err(|_| INVALID)?);
    }
    Ok(encoded)
}

/// Verify a certificate signature using its issuer's public key.
pub fn verify_certificate_signature(
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<(), Error> {
    if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
        return Err(INVALID);
    }
    let signature_algorithm = algorithm_identifier_contents(certificate.signature_algorithm())?;
    let public_key_algorithm = algorithm_identifier_contents(
        &issuer.tbs_certificate().subject_public_key_info().algorithm,
    )?;
    let algorithm = supported_signature_algorithms()
        .iter()
        .copied()
        .find(|algorithm| {
            algorithm.signature_alg_id().as_ref() == signature_algorithm
                && algorithm.public_key_alg_id().as_ref() == public_key_algorithm
        })
        .ok_or(INVALID)?;
    let public_key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or(INVALID)?;
    let message = certificate
        .tbs_certificate()
        .to_der()
        .map_err(|_| INVALID)?;
    let signature = certificate.signature().as_bytes().ok_or(INVALID)?;
    algorithm
        .verify_signature(public_key, &message, signature)
        .map_err(|_| INVALID)
}

/// Validate and return the uncompressed P-256 point in a certificate.
pub fn p256_public_point(certificate: &Certificate) -> Result<Vec<u8>, CertificateError> {
    let spki = certificate.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != EC_PUBLIC_KEY || algorithm_parameter_oid(spki)? != P256_CURVE {
        return Err(INVALID);
    }
    let point = spki.subject_public_key.as_bytes().ok_or(INVALID)?;
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: point.to_vec(),
    }
    .validate()
    .map_err(|_| INVALID)?;
    Ok(point.to_vec())
}

fn sha256_fingerprint(data: &[u8]) -> Fingerprint {
    let digest = crate::digest::HashAlgorithm::Sha256.digest(data);
    let mut fingerprint = [0; 32];
    fingerprint.copy_from_slice(&digest);
    fingerprint
}
