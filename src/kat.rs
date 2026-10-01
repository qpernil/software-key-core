//! Independent published known answers. Fixtures are committed and tests run offline.
use crate::post_quantum::*;
use serde_json::Value;
use std::io::Read;

fn load(data: &[u8]) -> Value {
    let mut text = String::new();
    flate2::read::GzDecoder::new(data)
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}
fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap_or("");
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn groups(data: &Value) -> &[Value] {
    data["testGroups"].as_array().unwrap()
}
fn cases(group: &Value) -> &[Value] {
    group["tests"].as_array().unwrap()
}
fn dsa(group: &Value) -> MlDsaParameterSet {
    match group["parameterSet"].as_str().unwrap() {
        "ML-DSA-44" => MlDsaParameterSet::MlDsa44,
        "ML-DSA-65" => MlDsaParameterSet::MlDsa65,
        "ML-DSA-87" => MlDsaParameterSet::MlDsa87,
        _ => panic!("parameter set"),
    }
}
fn kem(group: &Value) -> MlKemParameterSet {
    match group["parameterSet"].as_str().unwrap() {
        "ML-KEM-512" => MlKemParameterSet::MlKem512,
        "ML-KEM-768" => MlKemParameterSet::MlKem768,
        "ML-KEM-1024" => MlKemParameterSet::MlKem1024,
        _ => panic!("parameter set"),
    }
}
fn prehash(test: &Value) -> Option<MlDsaPrehash> {
    let id = match test["hashAlg"].as_str().unwrap() {
        "none" => return None,
        "SHA2-224" => 4,
        "SHA2-256" => 1,
        "SHA2-384" => 2,
        "SHA2-512" => 3,
        "SHA3-224" => 7,
        "SHA3-256" => 8,
        "SHA3-384" => 9,
        "SHA3-512" => 10,
        "SHAKE-128" => 11,
        "SHAKE-256" => 12,
        _ => panic!("hash algorithm"),
    };
    MlDsaPrehash::from_id(id)
}

#[test]
fn kat_fips204_key_generation_all_parameter_sets() {
    let data = load(include_bytes!(
        "../tests/vectors/nist/ml-dsa-keygen.json.gz"
    ));
    for group in groups(&data) {
        for test in cases(group) {
            let key = MlDsaPrivateKey::from_seed_slice(dsa(group), &hex(&test["seed"])).unwrap();
            assert_eq!(
                key.public_key(),
                hex(&test["pk"]),
                "pk tcId {}",
                test["tcId"]
            );
            assert_eq!(
                &*key.expanded_private_key(),
                &hex(&test["sk"]),
                "sk tcId {}",
                test["tcId"]
            );
        }
    }
}

#[test]
#[allow(deprecated)]
fn kat_fips204_pure_and_hash_signatures_all_parameter_sets() {
    let data = load(include_bytes!(
        "../tests/vectors/nist/ml-dsa-siggen.json.gz"
    ));
    for group in groups(&data) {
        for test in cases(group) {
            let message = hex(&test["message"]);
            let context = hex(&test["context"]);
            let encoded = hex(&test["sk"]);
            let rnd: [u8; 32] = if group["deterministic"] == true {
                [0; 32]
            } else {
                hex(&test["rnd"]).try_into().unwrap()
            };
            let mut input = if let Some(hash) = prehash(test) {
                hash.encode(&hash.digest(&message), &context).unwrap()
            } else {
                let mut input = vec![0, context.len() as u8];
                input.extend_from_slice(&context);
                input.extend_from_slice(&message);
                input
            };
            macro_rules! sign {
                ($params:ty) => {{
                    // Expanded private-key decoding is limited to trusted NIST fixtures.
                    let encoded =
                        ml_dsa::ExpandedSigningKeyBytes::<$params>::try_from(encoded.as_slice())
                            .unwrap();
                    let key = ml_dsa::ExpandedSigningKey::<$params>::from_expanded(&encoded);
                    key.sign_internal(&[&input], &rnd.into()).encode().to_vec()
                }};
            }
            let signature = match dsa(group) {
                MlDsaParameterSet::MlDsa44 => sign!(ml_dsa::MlDsa44),
                MlDsaParameterSet::MlDsa65 => sign!(ml_dsa::MlDsa65),
                MlDsaParameterSet::MlDsa87 => sign!(ml_dsa::MlDsa87),
            };
            assert_eq!(
                signature,
                hex(&test["signature"]),
                "signature tcId {}",
                test["tcId"]
            );
            let pk = hex(&test["pk"]);
            let verified = if let Some(hash) = prehash(test) {
                verify_ml_dsa_prehash(
                    dsa(group),
                    &pk,
                    &hash.digest(&message),
                    &context,
                    &signature,
                    hash,
                )
            } else {
                verify_ml_dsa(dsa(group), &pk, &message, &context, &signature)
            };
            assert!(verified.is_ok(), "verification tcId {}", test["tcId"]);
            input.clear();
        }
    }
}

#[test]
fn kat_fips204_valid_and_invalid_signature_verification() {
    let data = load(include_bytes!(
        "../tests/vectors/nist/ml-dsa-sigver.json.gz"
    ));
    for group in groups(&data) {
        for test in cases(group) {
            let message = hex(&test["message"]);
            let context = hex(&test["context"]);
            let pk = hex(&test["pk"]);
            let signature = hex(&test["signature"]);
            let result = if let Some(hash) = prehash(test) {
                verify_ml_dsa_prehash(
                    dsa(group),
                    &pk,
                    &hash.digest(&message),
                    &context,
                    &signature,
                    hash,
                )
            } else {
                verify_ml_dsa(dsa(group), &pk, &message, &context, &signature)
            };
            assert_eq!(
                result.is_ok(),
                test["testPassed"].as_bool().unwrap(),
                "tcId {} reason {}",
                test["tcId"],
                test["reason"]
            );
        }
    }
}

#[test]
fn kat_fips203_key_generation_all_parameter_sets() {
    let data = load(include_bytes!(
        "../tests/vectors/nist/ml-kem-keygen.json.gz"
    ));
    for group in groups(&data) {
        for test in cases(group) {
            let seed = [hex(&test["d"]), hex(&test["z"])].concat();
            let key = MlKemPrivateKey::from_seed_slice(kem(group), &seed).unwrap();
            assert_eq!(
                key.public_key(),
                hex(&test["ek"]),
                "ek tcId {}",
                test["tcId"]
            );
            assert_eq!(
                &*key.expanded_private_key(),
                &hex(&test["dk"]),
                "dk tcId {}",
                test["tcId"]
            );
        }
    }
}

#[test]
fn kat_fips203_encapsulation_decapsulation_rejection_and_key_checks() {
    let data = load(include_bytes!(
        "../tests/vectors/nist/ml-kem-encap-decap.json.gz"
    ));
    for group in groups(&data) {
        for test in cases(group) {
            let parameter_set = kem(group);
            let pk = hex(&test["ek"]);
            let dk = hex(&test["dk"]);
            match group["function"].as_str().unwrap() {
                "encapsulation" => {
                    let (c, k) = ml_kem_encapsulate_deterministic(
                        parameter_set,
                        &pk,
                        &hex(&test["m"]).try_into().unwrap(),
                    )
                    .unwrap();
                    assert_eq!(c, hex(&test["c"]), "ciphertext tcId {}", test["tcId"]);
                    assert_eq!(&*k, &hex(&test["k"]), "secret tcId {}", test["tcId"]);
                    let key =
                        MlKemPrivateKey::from_expanded_private_key(parameter_set, &dk).unwrap();
                    assert_eq!(&*key.decapsulate(&c).unwrap(), &hex(&test["k"]));
                }
                "decapsulation" => {
                    let key =
                        MlKemPrivateKey::from_expanded_private_key(parameter_set, &dk).unwrap();
                    assert_eq!(
                        &*key.decapsulate(&hex(&test["c"])).unwrap(),
                        &hex(&test["k"]),
                        "tcId {} reason {}",
                        test["tcId"],
                        test["reason"]
                    );
                }
                "decapsulationKeyCheck" => assert_eq!(
                    MlKemPrivateKey::from_expanded_private_key(parameter_set, &dk).is_ok(),
                    test["testPassed"].as_bool().unwrap(),
                    "dk tcId {}",
                    test["tcId"]
                ),
                "encapsulationKeyCheck" => assert_eq!(
                    ml_kem_encapsulate_deterministic(parameter_set, &pk, &[0; 32]).is_ok(),
                    test["testPassed"].as_bool().unwrap(),
                    "ek tcId {}",
                    test["tcId"]
                ),
                _ => panic!("unsupported KEM function"),
            }
        }
    }
}

use crate::digest::{HashAlgorithm, hkdf, hmac};
use crate::software_key_agreement::{
    MontgomeryCurve, SoftwareMontgomeryKey, derive_with_signing_key,
};
use crate::software_signing::{
    EcCurve, EdwardsCurve, SoftwareEcKey, SoftwarePublicKey, SoftwareSigningKey,
};
use crate::software_symmetric::*;

fn hash_algorithm(name: &str) -> HashAlgorithm {
    match name {
        "SHA-1" => HashAlgorithm::Sha1,
        "SHA-224" => HashAlgorithm::Sha224,
        "SHA-256" => HashAlgorithm::Sha256,
        "SHA-384" => HashAlgorithm::Sha384,
        "SHA-512" => HashAlgorithm::Sha512,
        "SHA3-224" => HashAlgorithm::Sha3_224,
        "SHA3-256" => HashAlgorithm::Sha3_256,
        "SHA3-384" => HashAlgorithm::Sha3_384,
        "SHA3-512" => HashAlgorithm::Sha3_512,
        _ => panic!("unsupported hash {name}"),
    }
}
fn ec_scalar_length(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P224 => 28,
        EcCurve::P256 | EcCurve::Secp256k1 | EcCurve::BrainpoolP256 => 32,
        EcCurve::P384 | EcCurve::BrainpoolP384 => 48,
        EcCurve::P521 => 66,
        EcCurve::BrainpoolP512 => 64,
    }
}
fn ec_curve(name: &str) -> EcCurve {
    match name {
        "secp224r1" => EcCurve::P224,
        "secp256r1" => EcCurve::P256,
        "secp384r1" => EcCurve::P384,
        "secp521r1" => EcCurve::P521,
        "secp256k1" => EcCurve::Secp256k1,
        "brainpoolP256r1" => EcCurve::BrainpoolP256,
        "brainpoolP384r1" => EcCurve::BrainpoolP384,
        "brainpoolP512r1" => EcCurve::BrainpoolP512,
        _ => panic!("unsupported curve {name}"),
    }
}
fn check_result(name: &str, test: &Value, success: bool) {
    match test["result"].as_str().unwrap() {
        "valid" => assert!(success, "{name} tcId {}: {}", test["tcId"], test["comment"]),
        "invalid" => assert!(
            !success,
            "{name} tcId {}: {}",
            test["tcId"], test["comment"]
        ),
        // Wycheproof explicitly permits rejection of these noncanonical inputs.
        "acceptable" => {}
        _ => panic!("unknown result"),
    }
}
fn check_output<E: std::fmt::Debug>(
    name: &str,
    test: &Value,
    result: Result<impl AsRef<[u8]>, E>,
    expected: &[u8],
) {
    check_result(name, test, result.is_ok());
    if let Ok(output) = result {
        assert_eq!(output.as_ref(), expected, "{name} tcId {}", test["tcId"]);
    }
}

#[test]
fn kat_wycheproof_ecdsa_all_supported_curves() {
    for (name, fixture) in ECDSA {
        let data = load(fixture);
        for group in groups(&data) {
            let curve = ec_curve(group["publicKey"]["curve"].as_str().unwrap());
            let key = SoftwarePublicKey::Ec {
                curve,
                uncompressed: hex(&group["publicKey"]["uncompressed"]),
            };
            let hash = hash_algorithm(group["sha"].as_str().unwrap());
            for test in cases(group) {
                check_result(
                    name,
                    test,
                    key.verify_prehash(
                        curve.signature_scheme(),
                        &hash.digest(&hex(&test["msg"])),
                        &hex(&test["sig"]),
                    )
                    .is_ok(),
                );
            }
        }
    }
}
#[test]
fn kat_wycheproof_ed25519_and_ed448() {
    for (fixtures, curve) in [
        (ED25519, EdwardsCurve::Ed25519),
        (ED448, EdwardsCurve::Ed448),
    ] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                let key = SoftwarePublicKey::Edwards {
                    curve,
                    public_key: hex(&group["publicKey"]["pk"]),
                };
                for test in cases(group) {
                    check_result(
                        name,
                        test,
                        key.verify_message(
                            curve.signature_scheme(),
                            &hex(&test["msg"]),
                            &hex(&test["sig"]),
                        )
                        .is_ok(),
                    );
                }
            }
        }
    }
}
#[test]
fn kat_wycheproof_rsa_pkcs1_and_pss() {
    for (fixtures, pss) in [(RSA_SIGNATURE, false), (RSA_PSS, true)] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                let key = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(&hex(&group["publicKey"]["modulus"])),
                    rsa::BigUint::from_bytes_be(&hex(&group["publicKey"]["publicExponent"])),
                )
                .unwrap();
                let hash = hash_algorithm(group["sha"].as_str().unwrap());
                for test in cases(group) {
                    let digest = hash.digest(&hex(&test["msg"]));
                    let signature = hex(&test["sig"]);
                    let result = if pss {
                        crate::rsa_signing::rsa_verify_pss_digest(
                            &key,
                            crate::rsa_signing::RsaPssParameters {
                                hash,
                                mgf_hash: hash_algorithm(group["mgfSha"].as_str().unwrap()),
                                salt_length: group["sLen"].as_u64().unwrap() as usize,
                            },
                            &digest,
                            &signature,
                        )
                    } else {
                        crate::rsa_signing::rsa_verify_pkcs1v15_digest(
                            &key, hash, &digest, &signature,
                        )
                    };
                    check_result(name, test, result.is_ok());
                }
            }
        }
    }
}
#[test]
fn kat_wycheproof_montgomery_key_agreement() {
    for (fixtures, curve) in [
        (X25519, MontgomeryCurve::X25519),
        (X448, MontgomeryCurve::X448),
    ] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                for test in cases(group) {
                    let key = SoftwareMontgomeryKey::from_serialized(curve, &hex(&test["private"]))
                        .unwrap();
                    check_output(
                        name,
                        test,
                        key.derive(&hex(&test["public"])),
                        &hex(&test["shared"]),
                    );
                }
            }
        }
    }
}
#[test]
fn kat_wycheproof_ecdh_all_supported_curves() {
    for (name, fixture) in ECDH {
        let data = load(fixture);
        for group in groups(&data) {
            let curve = ec_curve(group["curve"].as_str().unwrap());
            for test in cases(group) {
                let mut secret = hex(&test["private"]);
                // Source integers can omit leading zeroes or include a sign octet.
                while secret.len() > ec_scalar_length(curve) && secret[0] == 0 {
                    secret.remove(0);
                }
                if secret.len() < ec_scalar_length(curve) {
                    let mut padded = vec![0; ec_scalar_length(curve) - secret.len()];
                    padded.extend_from_slice(&secret);
                    secret = padded;
                }
                let result = SoftwareEcKey::from_serialized(curve, &secret)
                    .map(SoftwareSigningKey::Ec)
                    .map_err(|_| ())
                    .and_then(|key| {
                        derive_with_signing_key(&key, &hex(&test["publicSec1"])).map_err(|_| ())
                    });
                check_output(name, test, result, &hex(&test["shared"]));
            }
        }
    }
}
#[test]
fn kat_wycheproof_hmac_and_aes_cmac() {
    for (name, fixture) in HMAC.iter().chain(AES_CMAC) {
        let data = load(fixture);
        let algorithm = if name.starts_with("hmac_") {
            Some(hash_algorithm(
                &data["algorithm"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("HMAC")
                    .unwrap()
                    .replace("SHA3-", "SHA3_")
                    .replace("SHA", "SHA-")
                    .replace("SHA-3_", "SHA3-"),
            ))
        } else {
            None
        };
        for group in groups(&data) {
            for test in cases(group) {
                let key = hex(&test["key"]);
                let message = hex(&test["msg"]);
                let tag = hex(&test["tag"]);
                let result = if let Some(hash) = algorithm {
                    hmac(hash, &key, &message)
                        .map(|v| v.to_vec())
                        .map_err(|_| ())
                } else {
                    aes_cmac(&key, &message).map(|v| v.to_vec()).map_err(|_| ())
                };
                let length = group["tagSize"].as_u64().unwrap() as usize / 8;
                let matches = result.as_ref().is_ok_and(|out| {
                    tag.len() == length && out.get(..length) == Some(tag.as_slice())
                });
                check_result(name, test, matches);
            }
        }
    }
}
#[test]
fn kat_wycheproof_hkdf() {
    for (name, fixture) in HKDF {
        let data = load(fixture);
        let hash = hash_algorithm(
            data["algorithm"]
                .as_str()
                .unwrap()
                .strip_prefix("HKDF-")
                .unwrap(),
        );
        for group in groups(&data) {
            for test in cases(group) {
                check_output(
                    name,
                    test,
                    hkdf(
                        hash,
                        true,
                        true,
                        &hex(&test["ikm"]),
                        Some(&hex(&test["salt"])),
                        &hex(&test["info"]),
                        test["size"].as_u64().unwrap() as usize,
                    ),
                    &hex(&test["okm"]),
                );
            }
        }
    }
}
#[test]
fn kat_wycheproof_aes_gcm_and_ccm() {
    for (fixtures, ccm) in [(AES_GCM, false), (AES_CCM, true)] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                for test in cases(group) {
                    let key = hex(&test["key"]);
                    let iv = hex(&test["iv"]);
                    let aad = hex(&test["aad"]);
                    let message = hex(&test["msg"]);
                    let combined = [hex(&test["ct"]), hex(&test["tag"])].concat();
                    let tag_bits = group["tagSize"].as_u64().unwrap() as usize;
                    let crypt = |input: &[u8], encrypting| {
                        if ccm {
                            ccm_with(
                                message.len(),
                                &iv,
                                &aad,
                                tag_bits / 8,
                                input,
                                encrypting,
                                |op, blocks| match op {
                                    CcmOperation::EncryptBlocks => encrypt_aes_ecb(&key, blocks),
                                    CcmOperation::CbcMac => encrypt_aes_cbc(&key, &[0; 16], blocks)
                                        .map(|ciphertext| {
                                            ciphertext[ciphertext.len() - 16..].to_vec()
                                        }),
                                },
                            )
                            .map_err(|_| ())
                        } else {
                            gcm_with(&iv, &aad, tag_bits, input, encrypting, |blocks| {
                                encrypt_aes_ecb(&key, blocks)
                            })
                            .map_err(|_| ())
                        }
                    };
                    check_output(name, test, crypt(&combined, false), &message);
                    if test["result"] == "valid" {
                        assert_eq!(
                            crypt(&message, true).unwrap(),
                            combined,
                            "{name} tcId {}",
                            test["tcId"]
                        );
                    }
                }
            }
        }
    }
}
const AES_CBC_PKCS5: &[(&str, &[u8])] = &[(
    "aes_cbc_pkcs5_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_cbc_pkcs5_test.json.gz"),
)];

const AES_CCM: &[(&str, &[u8])] = &[(
    "aes_ccm_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_ccm_test.json.gz"),
)];

const AES_CMAC: &[(&str, &[u8])] = &[(
    "aes_cmac_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_cmac_test.json.gz"),
)];

const AES_GCM: &[(&str, &[u8])] = &[(
    "aes_gcm_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_gcm_test.json.gz"),
)];

const AES_GMAC: &[(&str, &[u8])] = &[(
    "aes_gmac_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_gmac_test.json.gz"),
)];

const AES_KWP: &[(&str, &[u8])] = &[(
    "aes_kwp_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_kwp_test.json.gz"),
)];

const AES_WRAP: &[(&str, &[u8])] = &[(
    "aes_wrap_test.json",
    include_bytes!("../tests/vectors/wycheproof/aes_wrap_test.json.gz"),
)];

const ECDH: &[(&str, &[u8])] = &[
    (
        "ecdh_brainpoolP256r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_brainpoolP256r1_test.json.gz"),
    ),
    (
        "ecdh_brainpoolP384r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_brainpoolP384r1_test.json.gz"),
    ),
    (
        "ecdh_brainpoolP512r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_brainpoolP512r1_test.json.gz"),
    ),
    (
        "ecdh_secp224r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_secp224r1_test.json.gz"),
    ),
    (
        "ecdh_secp256k1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_secp256k1_test.json.gz"),
    ),
    (
        "ecdh_secp256r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_secp256r1_test.json.gz"),
    ),
    (
        "ecdh_secp384r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_secp384r1_test.json.gz"),
    ),
    (
        "ecdh_secp521r1_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdh_secp521r1_test.json.gz"),
    ),
];

const ECDSA: &[(&str, &[u8])] = &[
    (
        "ecdsa_brainpoolP256r1_sha256_p1363_test.json",
        include_bytes!(
            "../tests/vectors/wycheproof/ecdsa_brainpoolP256r1_sha256_p1363_test.json.gz"
        ),
    ),
    (
        "ecdsa_brainpoolP384r1_sha384_p1363_test.json",
        include_bytes!(
            "../tests/vectors/wycheproof/ecdsa_brainpoolP384r1_sha384_p1363_test.json.gz"
        ),
    ),
    (
        "ecdsa_brainpoolP512r1_sha512_p1363_test.json",
        include_bytes!(
            "../tests/vectors/wycheproof/ecdsa_brainpoolP512r1_sha512_p1363_test.json.gz"
        ),
    ),
    (
        "ecdsa_secp224r1_sha224_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp224r1_sha224_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp224r1_sha256_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp224r1_sha256_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp224r1_sha512_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp224r1_sha512_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp256k1_sha256_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp256k1_sha256_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp256k1_sha512_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp256k1_sha512_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp256r1_sha256_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp256r1_sha512_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp256r1_sha512_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp384r1_sha384_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp384r1_sha384_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp384r1_sha512_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp384r1_sha512_p1363_test.json.gz"),
    ),
    (
        "ecdsa_secp521r1_sha512_p1363_test.json",
        include_bytes!("../tests/vectors/wycheproof/ecdsa_secp521r1_sha512_p1363_test.json.gz"),
    ),
];

const ED25519: &[(&str, &[u8])] = &[(
    "ed25519_test.json",
    include_bytes!("../tests/vectors/wycheproof/ed25519_test.json.gz"),
)];

const ED448: &[(&str, &[u8])] = &[(
    "ed448_test.json",
    include_bytes!("../tests/vectors/wycheproof/ed448_test.json.gz"),
)];

const HKDF: &[(&str, &[u8])] = &[
    (
        "hkdf_sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/hkdf_sha1_test.json.gz"),
    ),
    (
        "hkdf_sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/hkdf_sha256_test.json.gz"),
    ),
    (
        "hkdf_sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/hkdf_sha384_test.json.gz"),
    ),
    (
        "hkdf_sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/hkdf_sha512_test.json.gz"),
    ),
];

const HMAC: &[(&str, &[u8])] = &[
    (
        "hmac_sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha1_test.json.gz"),
    ),
    (
        "hmac_sha224_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha224_test.json.gz"),
    ),
    (
        "hmac_sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha256_test.json.gz"),
    ),
    (
        "hmac_sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha384_test.json.gz"),
    ),
    (
        "hmac_sha3_224_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha3_224_test.json.gz"),
    ),
    (
        "hmac_sha3_256_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha3_256_test.json.gz"),
    ),
    (
        "hmac_sha3_384_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha3_384_test.json.gz"),
    ),
    (
        "hmac_sha3_512_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha3_512_test.json.gz"),
    ),
    (
        "hmac_sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/hmac_sha512_test.json.gz"),
    ),
];

const RSA_OAEP: &[(&str, &[u8])] = &[
    (
        "rsa_oaep_2048_sha1_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha1_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha224_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha224_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha224_mgf1sha224_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha224_mgf1sha224_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha256_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha256_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha256_mgf1sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha384_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha384_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha384_mgf1sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha384_mgf1sha384_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha512_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha512_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_2048_sha512_mgf1sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_2048_sha512_mgf1sha512_test.json.gz"),
    ),
    (
        "rsa_oaep_3072_sha256_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_3072_sha256_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_3072_sha256_mgf1sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_3072_sha256_mgf1sha256_test.json.gz"),
    ),
    (
        "rsa_oaep_3072_sha512_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_3072_sha512_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_3072_sha512_mgf1sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_3072_sha512_mgf1sha512_test.json.gz"),
    ),
    (
        "rsa_oaep_4096_sha256_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_4096_sha256_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_4096_sha256_mgf1sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_4096_sha256_mgf1sha256_test.json.gz"),
    ),
    (
        "rsa_oaep_4096_sha512_mgf1sha1_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_4096_sha512_mgf1sha1_test.json.gz"),
    ),
    (
        "rsa_oaep_4096_sha512_mgf1sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_oaep_4096_sha512_mgf1sha512_test.json.gz"),
    ),
];

const RSA_PKCS1: &[(&str, &[u8])] = &[
    (
        "rsa_pkcs1_2048_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pkcs1_2048_test.json.gz"),
    ),
    (
        "rsa_pkcs1_3072_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pkcs1_3072_test.json.gz"),
    ),
    (
        "rsa_pkcs1_4096_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pkcs1_4096_test.json.gz"),
    ),
];

const RSA_PSS: &[(&str, &[u8])] = &[
    (
        "rsa_pss_2048_sha1_mgf1_20_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_2048_sha1_mgf1_20_test.json.gz"),
    ),
    (
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_2048_sha256_mgf1_0_test.json.gz"),
    ),
    (
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json.gz"),
    ),
    (
        "rsa_pss_2048_sha256_mgf1sha1_20_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_2048_sha256_mgf1sha1_20_test.json.gz"),
    ),
    (
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_2048_sha384_mgf1_48_test.json.gz"),
    ),
    (
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json.gz"),
    ),
    (
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_4096_sha256_mgf1_32_test.json.gz"),
    ),
    (
        "rsa_pss_4096_sha384_mgf1_48_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_4096_sha384_mgf1_48_test.json.gz"),
    ),
    (
        "rsa_pss_4096_sha512_mgf1_32_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_4096_sha512_mgf1_32_test.json.gz"),
    ),
    (
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json.gz"),
    ),
];

const RSA_SIGNATURE: &[(&str, &[u8])] = &[
    (
        "rsa_signature_2048_sha224_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha224_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha256_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha384_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha3_224_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha3_224_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha3_256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha3_256_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha3_384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha3_384_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha3_512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha3_512_test.json.gz"),
    ),
    (
        "rsa_signature_2048_sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_2048_sha512_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha256_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha384_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha3_256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha3_256_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha3_384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha3_384_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha3_512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha3_512_test.json.gz"),
    ),
    (
        "rsa_signature_3072_sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_3072_sha512_test.json.gz"),
    ),
    (
        "rsa_signature_4096_sha256_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_4096_sha256_test.json.gz"),
    ),
    (
        "rsa_signature_4096_sha384_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_4096_sha384_test.json.gz"),
    ),
    (
        "rsa_signature_4096_sha512_test.json",
        include_bytes!("../tests/vectors/wycheproof/rsa_signature_4096_sha512_test.json.gz"),
    ),
];

const X25519: &[(&str, &[u8])] = &[(
    "x25519_test.json",
    include_bytes!("../tests/vectors/wycheproof/x25519_test.json.gz"),
)];

const X448: &[(&str, &[u8])] = &[(
    "x448_test.json",
    include_bytes!("../tests/vectors/wycheproof/x448_test.json.gz"),
)];

#[test]
fn kat_wycheproof_rsa_oaep_and_pkcs1_decryption() {
    use rsa::pkcs8::DecodePrivateKey;
    for (fixtures, oaep) in [(RSA_OAEP, true), (RSA_PKCS1, false)] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                let key =
                    rsa::RsaPrivateKey::from_pkcs8_der(&hex(&group["privateKeyPkcs8"])).unwrap();
                for test in cases(group) {
                    let ciphertext = hex(&test["ct"]);
                    let result = if oaep {
                        let hash = hash_algorithm(group["sha"].as_str().unwrap());
                        crate::rsa_signing::rsa_decrypt_oaep_digest(
                            &key,
                            &ciphertext,
                            &hash.digest(&hex(&test["label"])),
                            hash_algorithm(group["mgfSha"].as_str().unwrap()),
                        )
                    } else {
                        crate::rsa_signing::rsa_decrypt_pkcs1v15(&key, &ciphertext)
                    };
                    check_output(name, test, result, &hex(&test["msg"]));
                }
            }
        }
    }
}
#[test]
fn kat_wycheproof_aes_cbc_padding() {
    for (name, fixture) in AES_CBC_PKCS5 {
        let data = load(fixture);
        for group in groups(&data) {
            for test in cases(group) {
                let key = hex(&test["key"]);
                let iv = hex(&test["iv"]);
                let message = hex(&test["msg"]);
                let ciphertext = hex(&test["ct"]);
                let result = decrypt_aes_cbc(&key, &iv, &ciphertext)
                    .map_err(|_| ())
                    .and_then(|plaintext| remove_pkcs7_padding(plaintext, 16).map_err(|_| ()));
                check_output(name, test, result, &message);
                if test["result"] == "valid" {
                    let padded = apply_pkcs7_padding(&message, 16).unwrap();
                    assert_eq!(
                        encrypt_aes_cbc(&key, &iv, &padded).unwrap(),
                        ciphertext,
                        "{name} tcId {}",
                        test["tcId"]
                    );
                }
            }
        }
    }
}
#[test]
fn kat_wycheproof_aes_gmac() {
    for (name, fixture) in AES_GMAC {
        let data = load(fixture);
        for group in groups(&data) {
            for test in cases(group) {
                let key = hex(&test["key"]);
                let iv = hex(&test["iv"]);
                let message = hex(&test["msg"]);
                let tag = hex(&test["tag"]);
                let computed = gcm_with(
                    &iv,
                    &message,
                    group["tagSize"].as_u64().unwrap() as usize,
                    &[],
                    true,
                    |blocks| encrypt_aes_ecb(&key, blocks),
                );
                check_result(name, test, computed.is_ok_and(|out| out == tag));
            }
        }
    }
}
#[test]
fn kat_wycheproof_aes_key_wrap_and_padding() {
    for (fixtures, padding) in [(AES_WRAP, false), (AES_KWP, true)] {
        for (name, fixture) in fixtures {
            let data = load(fixture);
            for group in groups(&data) {
                for test in cases(group) {
                    let key = hex(&test["key"]);
                    let message = hex(&test["msg"]);
                    let ciphertext = hex(&test["ct"]);
                    let crypt = |input: &[u8], encrypting| {
                        let block = |block: &[u8], encrypting| {
                            if encrypting {
                                encrypt_aes_ecb(&key, block)
                            } else {
                                decrypt_aes_ecb(&key, block)
                            }
                        };
                        if padding {
                            key_wrap_with_padding_with(
                                input,
                                encrypting,
                                &[0xa6, 0x59, 0x59, 0xa6],
                                block,
                            )
                        } else {
                            key_wrap_with(input, encrypting, &[0xa6; 8], block)
                        }
                    };
                    check_output(name, test, crypt(&ciphertext, false), &message);
                    if test["result"] == "valid" {
                        assert_eq!(
                            crypt(&message, true).unwrap(),
                            ciphertext,
                            "{name} tcId {}",
                            test["tcId"]
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn kat_nist_sha1_sha2_sha3_and_shake() {
    for fixture in [
        include_bytes!("../tests/vectors/nist/sha12.json.gz").as_slice(),
        include_bytes!("../tests/vectors/nist/sha3.json.gz").as_slice(),
        include_bytes!("../tests/vectors/nist/shake.json.gz").as_slice(),
    ] {
        let data = load(fixture);
        for group in groups(&data) {
            let algorithm = group["algorithm"].as_str().unwrap();
            for test in cases(group) {
                let mut message = hex(&test["Msg"]);
                if let Some(length) = test["Len"].as_str() {
                    let bits: usize = length.parse().unwrap();
                    assert_eq!(bits % 8, 0);
                    message.truncate(bits / 8);
                }
                let expected = hex(if algorithm.starts_with("SHAKE") {
                    &test["Output"]
                } else {
                    &test["MD"]
                });
                let mut state = if algorithm.starts_with("SHAKE") {
                    MlDsaPrehash::from_id(if algorithm == "SHAKE128" { 11 } else { 12 })
                        .unwrap()
                        .context()
                } else {
                    let name = algorithm
                        .replace("SHA3_", "SHA3-")
                        .replace("SHA1", "SHA-1")
                        .replace("SHA224", "SHA-224")
                        .replace("SHA256", "SHA-256")
                        .replace("SHA384", "SHA-384")
                        .replace("SHA512", "SHA-512");
                    let hash = hash_algorithm(&name);
                    assert_eq!(
                        hash.digest(&message),
                        expected,
                        "{} Len {}",
                        group["sourceFile"],
                        test["Len"]
                    );
                    // MlDsaPrehash covers SHA-2/3; SHA-1 uses the general streaming API.
                    let mut state = crate::digest::HashContext::new(hash);
                    for chunk in message.chunks(137) {
                        state.update(chunk);
                    }
                    assert_eq!(
                        state.finalize(),
                        expected,
                        "{} streaming Len {}",
                        group["sourceFile"],
                        test["Len"]
                    );
                    continue;
                };
                for chunk in message.chunks(137) {
                    state.update(chunk);
                }
                let actual = state.finalize();
                // Short/long SHAKE vectors specify 16/32 bytes; VariableOut includes
                // full 32/64-byte answers for the HashML-DSA output sizes.
                assert_eq!(
                    &actual[..expected.len()],
                    expected,
                    "{} Len {}",
                    group["sourceFile"],
                    test["Len"]
                );
            }
        }
    }
}
#[test]
fn kat_nist_triple_des_ecb_and_cbc() {
    let data = load(include_bytes!("../tests/vectors/nist/tdes.json.gz"));
    for group in groups(&data) {
        for test in cases(group) {
            let key = if test["KEYs"].is_string() {
                hex(&test["KEYs"]).repeat(3)
            } else {
                [hex(&test["KEY1"]), hex(&test["KEY2"]), hex(&test["KEY3"])].concat()
            };
            let plaintext = hex(&test["PLAINTEXT"]);
            let ciphertext = hex(&test["CIPHERTEXT"]);
            let (encrypted, decrypted) = if group["algorithm"] == "TDES-CBC" {
                let iv = hex(&test["IV"]).try_into().unwrap();
                (
                    encrypt_tdes_cbc(&key, &iv, &plaintext),
                    decrypt_tdes_cbc(&key, &iv, &ciphertext),
                )
            } else {
                (
                    encrypt_tdes_ecb(&key, &plaintext),
                    decrypt_tdes_ecb(&key, &ciphertext),
                )
            };
            assert_eq!(
                encrypted.unwrap(),
                ciphertext,
                "{} COUNT {}",
                group["sourceFile"],
                test["COUNT"]
            );
            assert_eq!(
                decrypted.unwrap(),
                plaintext,
                "{} COUNT {}",
                group["sourceFile"],
                test["COUNT"]
            );
        }
    }
}
