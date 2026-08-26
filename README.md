# software-key-core

`software-key-core` provides protocol-neutral software key operations shared by
security-token providers and device emulators.

The crate owns reusable RSA, elliptic-curve, Ed25519 and X25519 key generation,
public-key projection, signing, verification and raw key agreement. Its
symmetric primitives cover AES ECB/CBC/CTR, CCM with both general and Yubico
OTP profiles, GCM/GMAC, AES-CMAC, and AES key wrap with padding. GCM, general
CCM, CTR and CMAC also have callback-based forms which operate over a caller's
AES block capability, allowing one construction to serve raw software keys and
hardware-held keys. It also owns the reusable SCP03-style KDF, cryptogram and
padding operations, X9.63 and Yubico password KDFs, and both sides of the
ARKG-P256 public/private derivation. Supported Weierstrass curves include
P-224/P-256/P-384/P-521, secp256k1, and Brainpool P-256/P-384/P-512. Classical
asymmetric keys also support PKCS#8 import/export at protocol boundaries such
as YubiHSM RSA-AES key wrapping.

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
