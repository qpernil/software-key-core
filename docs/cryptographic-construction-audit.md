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
capability supplied by either software or hardware. AES-GCM over an AES ECB
block-encryption callback is the model example.

## Moved from `pkcs11rs`

The following constructions now live in `software-key-core` and retain thin
PKCS #11 parameter/error adapters in `pkcs11rs`:

| Construction | Shared lower-level capability | Hardware use |
| --- | --- | --- |
| AES-GCM and GMAC | AES ECB block encryption | YubiHSM ECB commands |
| AES-CTR | AES ECB block encryption | YubiHSM ECB commands |
| General AES-CCM | AES ECB encryption and CBC-MAC | YubiHSM ECB/CBC commands |
| AES-CMAC | AES ECB block encryption | YubiHSM ECB commands |

The shared APIs validate construction-level inputs, construct counters and
authentication data, verify tags in constant time, erase unauthenticated
plaintext, and reject malformed callback output. Callers retain key lookup,
authorization, mechanism parsing, hardware command chunking and native error
mapping.

## Already shared

These responsibilities were already in `software-key-core` before this audit:

- raw AES ECB/CBC, fixed-profile CCM, CMAC and AES-KWP;
- SCP03 KDF, cryptograms and ISO 7816 padding;
- RSA raw operations, PKCS #1 signing, PSS and OAEP for software keys;
- ECDSA, Ed25519, X25519 and Weierstrass ECDH operations;
- ML-DSA operations;
- ARKG-P256 derivation;
- Yubico password derivation; and
- the existing SHA-256 X9.63 KDF used by secure-channel code.

`virtual-yubihsm` already delegates its software cryptography to these APIs.
`virtual-yubikey` does the same for signing, symmetric operations, ML-DSA and
ARKG. Their remaining direct cryptographic calls are mostly protocol
composition and encoding.

## Next high-value migrations

### AES constructions over hardware block operations

`pkcs11rs` still contains callback-based implementations of:

- RFC 3394 AES Key Wrap with configurable initial value;
- RFC 5649 AES Key Wrap with Padding with configurable alternative initial
  value; and
- PKCS #7 padding around AES-CBC operations.

These should move next. The raw-key KWP API already in `software-key-core`
does not replace the callback form because a hardware-held key exposes block
operations rather than key bytes.

### RSA encodings over raw RSA operations

`pkcs11rs` retains OAEP encode/decode, PKCS #1 v1.5 encryption padding, PSS
encoding, MGF1 and DigestInfo construction for devices which expose raw RSA.
These are protocol-neutral constructions over a raw RSA capability and should
be consolidated with `software-key-core::rsa_signing`. PKCS #11 mechanism
parsing and device-specific raw-operation selection stay in `pkcs11rs`.

### Generic KDF and digest constructions

`pkcs11rs` has general SHA-1/SHA-2/SHA-3 X9.63 KDF, HKDF extract/expand and
MGF1 implementations. `software-key-core` currently exposes narrower variants
for its existing consumers. A shared digest enum and generic KDF APIs would
remove duplication while leaving PKCS #11 identifiers and output-object policy
in `pkcs11rs`.

### ML-KEM

ML-DSA is shared, but `pkcs11rs` still owns ML-KEM key generation,
serialization, encapsulation and decapsulation directly. Those raw FIPS 203
operations should join the post-quantum module. PKCS #11 parameter-set numbers,
attributes and object templates remain provider code.

### HMAC and legacy block modes

General HMAC helpers could remove direct HMAC implementations in each protocol
crate, though the benefit is smaller because RustCrypto already supplies the
common primitive. Triple-DES ECB/CBC/padding is isolated to PIV compatibility
and PKCS #11 software mechanisms; it is a lower-priority candidate because it
is legacy-only.

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
