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

`virtual-yubihsm` already delegates its software cryptography to these APIs.
`virtual-yubikey` does the same for signing, symmetric operations, ML-DSA and
ARKG. Their remaining direct cryptographic calls are mostly protocol
composition and encoding.

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

The remaining direct dependencies have protocol or key-representation work
which cannot be replaced by a construction callback:

| Consumer | Dependency class | Retained responsibility |
| --- | --- | --- |
| `pkcs11rs` | `p256`, `elliptic-curve`, `rsa` | Hardware public-key parsing, raw public operations, certificate and ECDH protocol values |
| `pkcs11rs` | `getrandom`, `subtle` | Protocol challenges, generated object material and constant-time protocol comparisons |
| `pkcs11rs-tool` | `p256` | Certificate/public-key authoring and validation |
| `virtual-yubihsm` | `p256`, `rsa` | YubiHSM asymmetric-authentication ECDH, attestation and wire-format public keys |
| `virtual-yubihsm` | `getrandom`, `subtle` | Device challenges, nonces and secure-session comparisons |
| `virtual-yubikey` | `p256` | CTAP PIN-protocol ECDH and public-point encoding |
| `virtual-yubikey` | `getrandom`, `subtle` | Credential identifiers, protocol nonces and PIN/authentication comparisons |

The additional curve crates in `virtual-yubikey` are now test-only: production
ECDSA DER formatting is supplied by `software-key-core`. No consumer retains a
direct AES, Triple-DES, CCM, CMAC, GHASH, HMAC, HKDF, PBKDF2, SHA-1, SHA-2,
SHA-3 or ML-KEM dependency.

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
