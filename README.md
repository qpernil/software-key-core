# software-key-core

`software-key-core` provides protocol-neutral software key operations and
optional durable-state mechanics shared by security-token providers and device
emulators.

The crate owns reusable RSA, elliptic-curve, Ed25519 and X25519 key generation,
public-key projection, signing, verification and raw key agreement. Its
symmetric adapters cover AES and Triple-DES, while its construction APIs cover
CBC, CTR, CMAC, CCM, GCM/GMAC, PKCS #7 padding, RFC 3394 key wrap and RFC 5649
key wrap with padding. The construction APIs operate over caller-supplied block
capabilities, allowing the same implementation to serve software keys and
hardware-held keys. AES-specific names are reserved for convenience APIs which
actually accept AES key bytes. `cmac_with_cbc` combines one block encryption
for CMAC subkeys with one unpadded, zero-IV CBC call for the complete prepared
message, reducing hardware round trips. It shares final-block/subkey handling
with the block-only `cmac_with` construction.

Digest support is similarly centralized: SHA-1, SHA-2 and SHA-3 hashing,
streaming hash contexts, HMAC, MGF1, X9.63 KDF, HKDF and PBKDF2-HMAC. RSA
PKCS #1 v1.5, OAEP and PSS encodings can be composed with caller-supplied raw
RSA operations, independently of where the key lives. ML-KEM and ML-DSA key
operations and serialization are shared as well. Fixed-width/DER ECDSA
signature conversion is likewise key-implementation independent. The crate also owns SCP03
KDF, cryptogram and padding operations, the Yubico password KDF, and both sides
of the ARKG-P256 public/private derivation. Supported Weierstrass curves include
P-224/P-256/P-384/P-521, secp256k1, and Brainpool P-256/P-384/P-512. Classical
asymmetric keys also support PKCS#8 import/export at protocol boundaries such
as YubiHSM RSA-AES key wrapping.

The `counter_kdf` module supplies a single-output SP 800-108 AES-CMAC counter
KDF with caller-ordered byte arrays, one iteration counter, and an optional
encoded output length. It supports AES-128/192/256 base keys, byte-aligned
8–32-bit counters, 8–64-bit length fields, both byte orders, and requested-key
or generated-segment length accounting. Results and working buffers use
zeroizing storage. `cmac_counter_kdf_with` accepts a fallible CMAC operation,
allowing hardware key handles without exporting their values. The byte-key
convenience function uses the same engine. All fields are validated before
invoking CMAC; callback failures discard partial output and propagate to the
caller. The caller retains output-size limits and object policy;
PKCS #11 parameter parsing and permissions remain in pkcs11rs. Independent
OpenSSL-CMAC vectors cover SCP03 layouts and multi-block truncation.

ML-DSA public-key validation and SubjectPublicKeyInfo encoding operate on the
fixed-size raw encoding without expanding a verification matrix. Every
correctly sized FIPS 204 public-key encoding is decodable. Tests compare DER
against the upstream encoder for all parameter sets and exercise metadata
operations on a 64 KiB stack. With allocation enabled, the pinned ML-DSA
implementation stores private matrices as `MaybeBox` rows, so sampling and
cloning avoid a full inline matrix. The public lattice types and constructors
are unchanged; other vectors and intermediate values still use stack space.
Private-key generation and import, public-key construction, signing, and
verification run directly on the caller's thread. Tests cover all three
ML-DSA parameter sets on 512 KiB stacks, including unoptimized builds. This is
a tested configuration rather than a portable bound; callers need additional
headroom for their own stack frames.
Cloned ML-DSA and ML-KEM handles share immutable expanded key state through
`Arc`. RSA handles similarly share the private key and its CRT precomputation.
Cloning does not duplicate key material or spawn a worker. Each underlying key
is zeroized when its last owner is dropped; object metadata and policy remain
owned by the caller. Sharing and last-owner release are covered by clone-lifetime
tests, including signing/decryption or decapsulation after the original is dropped.

`MlDsaPrivateKey::sign_prehash` and `verify_ml_dsa_prehash` implement FIPS 204
HashML-DSA for caller-computed digests. `MlDsaPrehash` validates SHA-2, SHA-3,
and SHAKE digest lengths and constructs the domain separator, context, and DER
hash OID. Pure ML-DSA uses the existing message operations. Context length is
0–255 bytes inclusive for both modes. `MlDsaPrehash::context` exposes clonable
incremental SHA-2/SHA-3/SHAKE hashing; `digest` supplies the one-shot equivalent.

### Concrete hybrid KEM specification profile

The `hybrid_kem` module implements exactly
`draft-irtf-cfrg-concrete-hybrid-kems-04` (6 July 2026), with the generic CG
framework fixed by `draft-irtf-cfrg-hybrid-kems-12`. The three supported
constructions are `MLKEM768-P256`, `MLKEM768-X25519`, and
`MLKEM1024-P384`; the X25519 construction is byte-for-byte the X-Wing
construction in `draft-connolly-cfrg-xwing-kem-10`.

The component specifications are FIPS 203 for ML-KEM, FIPS 202 for SHAKE256
and SHA3-256, SEC 1 version 2.0 uncompressed point encoding for P-256/P-384,
and RFC 7748 for X25519. Public keys are `ek_PQ || ek_T`, ciphertexts are
`ct_PQ || ct_T`, and the combiner returns 32 bytes. The respective public-key
lengths are 1249, 1216, and 1665 bytes; ciphertext lengths are 1153, 1120, and
1665 bytes. A private key is the draft's single 32-byte seed. The library
derives both components internally and never exposes either private component
as a separately usable key. Official draft-04 vectors cover all three
constructions, alongside malformed-point, non-contributory-X25519, and
cross-construction rejection tests.

The optional `x509-signing` feature provides standard SubjectPublicKeyInfo
projection and X.509 certificate-signing adapters for software keys, including
ML-DSA certificate signatures. Callers
retain certificate profiles, names, extensions, validity, serial-number policy,
and protocol error mapping. The separate `x509-validation` feature provides
strict certificate parsing, signature verification, and certificate-chain
validation. Trust is supplied explicitly as CA certificates or a P-256 CA public
key; presented certificates never become anchors.

Private-key identity and operations are separate in the API. `KeyKind`
selects what is generated or restored, including the RSA modulus size, while
`SignatureScheme` selects the digest and padding used by one operation. Runtime
owners retain parsed keys through the protocol-neutral `SoftwarePrivateKey`
union: RSA CRT precomputation, Ed25519 expansion, EC public
derivation, X25519 setup, and ML-DSA/ML-KEM expansion happen when a key crosses
the generation/import/restore boundary rather than for every command. Compact
seeds, scalars, RSA components, and PKCS#8 are boundary representations only.
Private key allocations are zeroized on final-owner drop, and exported private
bytes are returned in zeroizing buffers.

The opt-in Unix `state-persistence` feature provides an exclusive state-file
lock, atomic mode-`0600` replacement with file and directory sync, and a
background coordinator for immediate or batched writes, flushes, and failure
reporting. Callers supply the state path and encoder, or use
`StatePersistence::start_with_writer` to supply a durable writer for a batch of
independent records. A successful writer must complete every write in its
snapshot before acknowledging the corresponding mutation epochs. Callers retain
the serialized format, state-file naming, restoration and factory policy,
mutation decisions, and device lifecycle. The lock guard explicitly releases the kernel lock on
drop, so a descriptor inherited during subprocess creation cannot delay state
reopening after shutdown. The separate lock file remains on disk.

The crate does not own device- or protocol-specific identifiers and encodings,
PKCS #11 types, device authorization, object lifecycle, transport framing,
session state, or protocol-specific error mapping. Standard X.509 SPKI and
certificate-signature encoding are shared; certificate profiles and extensions
remain with callers. In particular, ARKG COSE/CBOR stays with the previewSign
callers, and SCP03 session counters and message framing stay with the
device/provider protocol layers.

The local consumers intentionally use dependency-by-path so each working
directory directly represents the code being built:

```text
software-key-core
├── ../pkcs11rs
├── ../virtual-yubikey
└── ../virtual-yubihsm
```

## Development

Rust 1.95 or newer is required. CI checks that minimum as well as stable Rust.

Run the standalone test suite with:

```console
cargo test --locked
cargo test --locked kat_
```

The [published known-answer test coverage](docs/known-answer-tests.md) includes
FIPS 203/204 for every parameter set, NIST SHA/Triple-DES and Wycheproof
classical signature, agreement, MAC, KDF, AEAD and key-wrap corpora.

The crate is not currently published. Consumers should continue using the
local path until repository and release metadata are established.

The current cross-project ownership review is recorded in the
[cryptographic-construction audit](docs/cryptographic-construction-audit.md).
