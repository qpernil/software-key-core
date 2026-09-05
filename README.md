# software-key-core

`software-key-core` provides protocol-neutral software key operations shared by
security-token providers and device emulators.

The crate owns reusable RSA, elliptic-curve, Ed25519 and X25519 key generation,
public-key projection, signing, verification and raw key agreement. Its
symmetric adapters cover AES and Triple-DES, while its construction APIs cover
CBC, CTR, CMAC, CCM, GCM/GMAC, PKCS #7 padding, RFC 3394 key wrap and RFC 5649
key wrap with padding. The construction APIs operate over caller-supplied block
capabilities, allowing the same implementation to serve software keys and
hardware-held keys. AES-specific names are reserved for convenience APIs which
actually accept AES key bytes.

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

The optional `x509` feature provides strict certificate parsing, signature
verification, and certificate-chain validation. Trust is supplied explicitly as
CA certificates or a P-256 CA public key; presented certificates never become
anchors. Providers retain their trust-selection and authorization policy.

Private-key identity and operations are separate in the API. `KeyKind`
selects what is generated or restored, including the RSA modulus size, while
`SignatureScheme` selects the digest and padding used by one operation. Runtime
owners retain parsed keys through the protocol-neutral `SoftwarePrivateKey`
union: RSA CRT precomputation, Ed25519 expansion, EC public
derivation, X25519 setup, and ML-DSA/ML-KEM expansion happen when a key crosses
the generation/import/restore boundary rather than for every command. Compact
seeds, scalars, RSA components, and PKCS#8 are boundary representations only.
All typed private-key wrappers guarantee zeroization on drop, and exported
private bytes are returned in zeroizing buffers.

It does not own protocol identifiers or encodings, PKCS #11 types, device
authorization, object lifecycle, persistence, transport framing, session
state, or protocol-specific error mapping. In particular, ARKG COSE/CBOR stays
with the previewSign callers, and SCP03 session counters and message framing
stay with the device/provider protocol layers.

The local consumers intentionally use dependency-by-path so each working
directory directly represents the code being built:

```text
software-key-core
├── ../pkcs11rs
├── ../virtual-yubikey
└── ../virtual-yubihsm
```

## Development

Run the standalone test suite with:

```console
cargo test
```

The crate is not currently published. Consumers should continue using the
local path until repository and release metadata are established.

The current cross-project ownership review is recorded in the
[cryptographic-construction audit](docs/cryptographic-construction-audit.md).
