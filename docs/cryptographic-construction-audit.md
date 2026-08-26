# Cryptographic construction ownership audit

## Scope

This audit covers the local Rust security-token projects which consume
`software-key-core`: `pkcs11rs`, `virtual-yubikey`, and `virtual-yubihsm`.
Transport, display, supervisor and unrelated application repositories do not
contain competing cryptographic implementations. Vendored or upstream firmware
trees are outside the ownership boundary and must not be rewritten as local
shared code.

The deciding question is not only whether an algorithm uses a software key.
A protocol-neutral construction belongs here when it can operate over a
capability supplied by either software or hardware. GCM over a caller-supplied
128-bit block-encryption capability is the model example.

## Moved from `pkcs11rs`

The following constructions now live in `software-key-core` and retain thin
PKCS #11 parameter/error adapters in `pkcs11rs`:

| Construction | Shared lower-level capability | Hardware use |
| --- | --- | --- |
| GCM and GMAC | 128-bit block encryption | YubiHSM AES ECB commands |
| CTR | block encryption | YubiHSM AES ECB commands |
| CCM | 128-bit block encryption and CBC-MAC | YubiHSM AES ECB/CBC commands |
| CMAC | 64- or 128-bit block encryption | YubiHSM AES ECB commands |
| CBC | block encryption/decryption | software AES and Triple-DES adapters |
| RFC 3394/5649 key wrapping | 128-bit block encryption/decryption | YubiHSM AES ECB commands |
| PKCS #7 padding | block length | PKCS #11 AES/Triple-DES mechanisms |
| RSA PKCS #1 v1.5, OAEP and PSS encodings | raw RSA operation | software, PIV and YubiHSM paths |
| ECDSA fixed-width/DER conversion | curve coordinate width | PIV and CTAP/FIDO paths |
| HMAC, MGF1, X9.63, HKDF and PBKDF2-HMAC | selected shared digest | all providers and emulators |
| ML-KEM | raw FIPS 203 key material | PKCS #11 software objects |

The shared APIs validate construction-level inputs, construct counters and
authentication data, verify tags in constant time, erase unauthenticated
plaintext, and reject malformed callback output. Callers retain key lookup,
authorization, mechanism parsing, hardware command chunking and native error
mapping.

## Shared algorithm adapters

These responsibilities were already in `software-key-core` before this audit:

- raw AES ECB and Triple-DES ECB, plus convenience adapters for the shared
  block constructions;
- SCP03 KDF, cryptograms and ISO 7816 padding;
- RSA raw operations and key-based conveniences over the shared RSA encodings;
- ECDSA, Ed25519, X25519 and Weierstrass ECDH operations;
- ML-DSA operations;
- ARKG-P256 derivation;
- Yubico password derivation; and
- ML-KEM and ML-DSA key operations and serialization.

All supported ECDSA curves, Ed25519 signing and verification, X25519, and
Weierstrass ECDH now cross the same shared key boundary. Static and ephemeral
P-256 agreement use the same `SoftwareSigningKey` and
`derive_with_signing_key` operations; key lifetime is a caller policy rather
than a separate cryptographic implementation.

`virtual-yubihsm` delegates device-static and ephemeral agreement, object ECDH,
X25519, object signing, and attestation-certificate signatures to these APIs.
`virtual-yubikey` does the same for CTAP agreement and all credential signing.
`pkcs11rs` delegates CTAP, SCP11 and YubiHSM agreement, public-point validation,
ECDSA/Ed25519 verification, and derived P-256 authentication keys.

## Completed migrations

The previously identified key-wrap, padding, RSA encoding, generic digest/KDF,
HMAC, Triple-DES and ML-KEM candidates have moved. Consumers now retain thin
parameter, capability-selection and error adapters. Their direct dependencies
on AES, Triple-DES, HMAC, HKDF, PBKDF2, SHA-1, SHA-2, SHA-3 and ML-KEM were
removed when no independent algorithm-level use remained.

Construction names intentionally do not contain `Aes`: `GcmError`,
`KeyWrapError` and `BlockCipherModeError` describe the reusable layer. Names
such as `encrypt_aes_cbc` remain only where an API accepts raw AES key bytes.
The RSA encoding family uses `RsaConstructionError`, rather than the narrower
`RsaSignatureError`, because the same layer owns signing and encryption
encodings.

## Remaining consumer cryptographic dependencies

The remaining production cryptographic dependencies have non-duplicated key
representation or protocol work:

| Consumer | Dependency class | Retained responsibility |
| --- | --- | --- |
| `pkcs11rs` | `rsa` | PKCS #11/YubiHSM RSA key representation and raw public operations |
| `pkcs11rs` | `getrandom`, `subtle` | Protocol challenges, generated object material and constant-time protocol comparisons |
| `pkcs11rs-tool` | none of the curve crates | Certificate containers are parsed locally; curve keys are validated by the shared API |
| `virtual-yubihsm` | `rsa`, `signature` | RSA wire-key representation and an X.509 builder adapter which calls shared signing |
| `virtual-yubihsm` | `getrandom`, `subtle` | Device challenges, nonces and secure-session comparisons |
| `virtual-yubikey` | `getrandom`, `subtle` | Credential identifiers, protocol nonces and PIN/authentication comparisons |

Curve and Ed25519 crates in consumers are test-only, except that `pkcs11rs`
keeps P-256 as an optional ABI-test fixture dependency. Those tests provide an
independent implementation against which the shared code is checked. No
consumer retains a default production dependency on a curve implementation,
or a direct AES, Triple-DES, CCM, CMAC, GHASH, HMAC, HKDF, PBKDF2, SHA-1,
SHA-2, SHA-3 or ML-KEM dependency.

## RSA implementation follow-up

The current shared implementation uses the stable pure-Rust `rsa` 0.9.10
release with `num-bigint-dig` 0.8.6 and 64-bit digits. Private operations are
not naive full-modulus exponentiation: generated and imported keys precompute
the CRT parameters, and signing/decryption uses CRT, random blinding and a
public-operation check of the recombined result. The bigint backend uses
windowed Montgomery exponentiation. Retaining a pure-Rust implementation is
preferred over adopting OpenSSL, AWS-LC or another FFI backend merely for
speed.

RustCrypto `rsa` 0.10.0-rc.18 replaces `num-bigint-dig` with the pure-Rust
`crypto-bigint` and `crypto-primes` stack. A release-build comparison performed
on an Apple M5 on 2026-08-26 produced the following results. RSA key-generation
times are naturally noisy because prime search is probabilistic.

| Implementation | RSA-4096 key generation mean | Median | Blinded RSA-4096 private operation |
| --- | ---: | ---: | ---: |
| `rsa` 0.9.10 | 1.089 s | 1.143 s | 4.9-5.0 ms |
| `rsa` 0.10.0-rc.18 | 0.431 s | 0.441 s | 5.4-5.5 ms |

The key-generation figures are ten independent keys per implementation. The
private-operation figures are two runs of twenty PKCS #1 v1.5 decryptions. The
release candidate was approximately 2.5 times faster for RSA-4096 generation,
but approximately 10 percent slower for an existing-key private operation. Its
built-in RSA key generation remained single-threaded during this measurement.

Version 0.10 retains the capabilities required by the shared layer: CRT and
precomputation, blinding and CRT-result verification, raw public/private
operations, construction from `p` and `q`, RSA-4096 generation, and the
PKCS #1 v1.5, OAEP and PSS schemes. Migration nevertheless requires adapting
the shared boundary from `BigUint` to precision-bearing `BoxedUint`, retrieving
`qInv` from Montgomery form for CRT export, and retesting every raw-operation
and encoding path.

Do not adopt the release candidate solely to improve virtual-device
provisioning time. Reconsider the migration when RustCrypto publishes a stable
0.10 release. At that point, repeat the benchmarks on macOS and the `ubuntu3`
deployment target, review the then-current upstream RSA side-channel status,
and run the complete `software-key-core`, `pkcs11rs`, `virtual-yubihsm` and
`virtual-yubikey` suites before changing the shared dependency.

## Constructions which should remain protocol-specific

The following combine shared primitives but encode protocol rules and should
not be moved wholesale into `software-key-core`:

- CTAP PIN/UV Auth protocol 1 and 2 key layout, labels, IV framing and tag
  truncation;
- OpenPGP iterated-and-salted S2K;
- SCP03/SCP11 session state, counters and message framing;
- YubiHSM command authorization, objects, audit and wrapped-object formats;
- PKCS #11 mechanism parsing, multipart operation state and return-code
  mapping; and
- COSE, CBOR, APDU, DER and connector transport framing.

These layers should consume shared primitive and callback-construction APIs but
retain their protocol-level composition.

## Migration rule

A migration is complete only when:

1. the construction has direct standard-vector tests in `software-key-core`;
2. software and hardware-backed consumer tests exercise the same shared code;
3. protocol-specific parsing and errors remain in the caller;
4. unauthenticated plaintext is erased before an error is returned;
5. malformed hardware callback output fails closed; and
6. the consumer no longer depends directly on a crate used only by the moved
   construction.
