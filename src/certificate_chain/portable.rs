//! RFC 5280 path validation, including critical certificate policies.
use super::*;
use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    EXTS_OF_INTEREST, ExtensionProcessing, PDVCertificate, PkiEnvironment, TaSource,
    TimeOfInterest,
};

pub(super) fn validate(
    trust: &CertificateTrust,
    certificates: &[Vec<u8>],
) -> Result<ParsedCertificate, Error> {
    if certificates.is_empty() || certificates.len() > 8 {
        return Err(INVALID);
    }
    let presented = parse_unique(certificates)?;
    if presented.last().ok_or(INVALID)?.is_ca {
        return Err(INVALID);
    }
    let now = UnixTime::now().as_secs();
    // Check canonical DER, critical-extension support, and validity for all presented certificates.
    if presented.iter().any(|c| !c.is_valid_at(now)) {
        return Err(INVALID);
    }
    let time = TimeOfInterest::from_unix_secs(now).map_err(|_| INVALID)?;
    let mut settings = CertificationPathSettings::new();
    settings.set_time_of_interest(time);
    settings.set_check_revocation_status(false);
    settings.set_require_ta_store(true);
    settings.set_forbid_self_signed_ee(true);
    settings.set_enforce_trust_anchor_validity(true);
    settings.set_enforce_trust_anchor_constraints(true);
    let mut environment = PkiEnvironment::default();
    environment.populate_5280_pki_environment();
    // Keep the existing ring-backed algorithm allowlist for certificate signatures.
    environment.clear_verify_signature_digest_callbacks();
    environment.clear_verify_signature_message_callbacks();
    environment.add_verify_signature_message_callback(verify_signature);
    let mut anchors = TaSource::new();
    let mut source = CertSource::new();
    for (i, encoded) in trust.local_certificates.iter().enumerate() {
        let cert = ParsedCertificate::parse(encoded)?;
        let file = CertFile {
            filename: format!("configured-{i}"),
            bytes: encoded.clone(),
        };
        if trust.root_fingerprints.contains(&cert.fingerprint) {
            anchors.push(file);
        } else {
            source.push(file);
        }
    }
    for (i, encoded) in certificates[..certificates.len() - 1].iter().enumerate() {
        source.push(CertFile {
            filename: format!("presented-{i}"),
            bytes: encoded.clone(),
        });
    }
    anchors.initialize().map_err(|_| INVALID)?;
    environment.add_trust_anchor_source(Box::new(anchors));
    source.initialize(&settings).map_err(|_| INVALID)?;
    source.find_all_partial_paths(&environment, &settings);
    environment.add_certificate_source(Box::new(source));
    let leaf = certificates.last().ok_or(INVALID)?;
    let mut target = PDVCertificate::try_from(leaf.as_slice()).map_err(|_| INVALID)?;
    target.parse_extensions(EXTS_OF_INTEREST);
    let mut paths = Vec::new();
    environment
        .get_paths_for_target(&target, &mut paths, 0, time)
        .map_err(|_| INVALID)?;
    for path in paths {
        let Ok(path_settings) =
            certval::enforce_trust_anchor_constraints(&settings, &path.trust_anchor)
        else {
            continue;
        };
        let mut results = CertificationPathResults::new();
        if environment
            .validate_path(&environment, &path_settings, &path, &mut results)
            .is_ok()
        {
            return ParsedCertificate::parse(leaf);
        }
    }
    Err(INVALID)
}

fn verify_signature(
    _environment: &PkiEnvironment,
    message: &[u8],
    signature: &der::asn1::BitString,
    algorithm: &spki::AlgorithmIdentifierOwned,
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> certval::Result<()> {
    let failure = || {
        certval::Error::PathValidation(certval::PathValidationStatus::SignatureVerificationFailure)
    };
    let sig_alg = algorithm_identifier_contents(algorithm).map_err(|_| failure())?;
    let key_alg = algorithm_identifier_contents(&spki.algorithm).map_err(|_| failure())?;
    let supported = supported_signature_algorithms()
        .iter()
        .copied()
        .find(|candidate| {
            candidate.signature_alg_id().as_ref() == sig_alg
                && candidate.public_key_alg_id().as_ref() == key_alg
        })
        .ok_or(certval::Error::Unrecognized)?;
    supported
        .verify_signature(
            spki.subject_public_key.as_bytes().ok_or_else(failure)?,
            message,
            signature.as_bytes().ok_or_else(failure)?,
        )
        .map_err(|_| failure())
}
