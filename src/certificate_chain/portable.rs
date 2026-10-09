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
    let mut anchor_files = Vec::new();
    let mut source_files = Vec::new();
    for (i, encoded) in trust.local_certificates.iter().enumerate() {
        let cert = ParsedCertificate::parse(encoded)?;
        let file = CertFile {
            filename: format!("configured-{i}"),
            bytes: encoded.clone(),
        };
        if trust.root_fingerprints.contains(&cert.fingerprint) {
            anchor_files.push(file);
        } else {
            source_files.push(file);
        }
    }
    validate_files(anchor_files, source_files, certificates)
}

/// RFC 5914 represents the caller's fixed CA key without inventing a signed
/// certificate. Presented issuer names choose paths, never additional trust.
pub(super) fn validate_with_p256_ca_key(
    point: &[u8],
    certificates: &[Vec<u8>],
) -> Result<ParsedCertificate, Error> {
    use x509_cert::anchor::{CertPathControls, TrustAnchorChoice, TrustAnchorInfo};
    if certificates.is_empty() || certificates.len() > 8 {
        return Err(INVALID);
    }
    let spki = spki::SubjectPublicKeyInfoOwned {
        algorithm: spki::AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(der::Any::encode_from(&P256_CURVE).map_err(|_| INVALID)?),
        },
        subject_public_key: der::asn1::BitString::from_bytes(point).map_err(|_| INVALID)?,
    };
    let key_id = der::asn1::OctetString::new(crate::digest::HashAlgorithm::Sha1.digest(point))
        .map_err(|_| INVALID)?;
    let mut anchors = Vec::new();
    let mut names = HashSet::new();
    let parsed = parse_unique(certificates)?;
    for (i, certificate) in parsed.iter().enumerate() {
        // A presented issuer must be traversed unless it actually carries the
        // configured anchor key. Otherwise a same-name anchor can hide the
        // intermediate path before the path builder verifies its signatures.
        let issuers: Vec<_> = parsed
            .iter()
            .filter(|c| c.subject == certificate.issuer)
            .collect();
        if !issuers.is_empty()
            && !issuers
                .iter()
                .any(|c| c.p256_public_point().is_ok_and(|p| p == point))
        {
            continue;
        }
        if !names.insert(certificate.issuer.clone()) {
            continue;
        }
        let anchor: TrustAnchorChoice = TrustAnchorChoice::TaInfo(TrustAnchorInfo {
            version: Default::default(),
            pub_key: spki.clone(),
            key_id: key_id.clone(),
            ta_title: None,
            cert_path: Some(CertPathControls {
                ta_name: x509_cert::name::Name::from_der(&certificate.issuer)
                    .map_err(|_| INVALID)?,
                certificate: None,
                policy_set: None,
                policy_flags: None,
                name_constr: None,
                path_len_constraint: None,
            }),
            extensions: None,
            ta_title_lang_tag: None,
        });
        anchors.push(CertFile {
            filename: format!("configured-key-{i}"),
            bytes: anchor.to_der().map_err(|_| INVALID)?,
        });
    }
    validate_files(anchors, Vec::new(), certificates)
}

fn validate_files(
    anchor_files: Vec<CertFile>,
    source_files: Vec<CertFile>,
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
    for file in anchor_files {
        anchors.push(file);
    }
    for file in source_files {
        source.push(file);
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

#[cfg(test)]
mod tests {
    use super::*;
    // Public DER vectors generated with Python cryptography. Issuing private
    // keys were discarded; the valid certificates expire in 2099.
    const ROOT: &[u8] = include_bytes!("fixtures/bare-ca.der");
    const LEAF: &[u8] = include_bytes!("fixtures/bare-ca-oce.der");

    #[test]
    fn bare_ca_key_validates_critical_policy_direct_and_intermediate_paths() {
        let point = ParsedCertificate::parse(ROOT)
            .unwrap()
            .p256_public_point()
            .unwrap();
        let expected = ParsedCertificate::parse(LEAF)
            .unwrap()
            .p256_public_point()
            .unwrap();
        for chain in [
            vec![LEAF.to_vec()],
            vec![ROOT.to_vec(), LEAF.to_vec()],
            vec![
                include_bytes!("fixtures/bare-ca-intermediate.der").to_vec(),
                include_bytes!("fixtures/bare-ca-oce-intermediate.der").to_vec(),
            ],
        ] {
            assert_eq!(
                CertificateTrust::validate_with_p256_ca_key(&point, &chain).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn bare_ca_key_rejects_wrong_keys_expiry_tampering_and_bad_extensions() {
        let point = ParsedCertificate::parse(ROOT)
            .unwrap()
            .p256_public_point()
            .unwrap();
        let wrong = ParsedCertificate::parse(LEAF)
            .unwrap()
            .p256_public_point()
            .unwrap();
        assert!(
            CertificateTrust::validate_with_p256_ca_key(&wrong, &[ROOT.to_vec(), LEAF.to_vec()])
                .is_err()
        );
        assert!(
            CertificateTrust::validate_with_p256_ca_key(&point[1..], &[LEAF.to_vec()]).is_err()
        );
        for leaf in [
            include_bytes!("fixtures/bare-ca-oce-expired.der").as_slice(),
            include_bytes!("fixtures/bare-ca-oce-unknown-critical.der").as_slice(),
            include_bytes!("fixtures/bare-ca-oce-malformed-policy.der").as_slice(),
        ] {
            assert!(CertificateTrust::validate_with_p256_ca_key(&point, &[leaf.to_vec()]).is_err());
        }
        let mut tampered = LEAF.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(CertificateTrust::validate_with_p256_ca_key(&point, &[tampered]).is_err());
    }
}
