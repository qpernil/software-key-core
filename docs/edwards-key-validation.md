# Edwards key validation

Ed25519 private inputs are 32-byte seeds and Ed448 private inputs are 57-byte
seeds. Every byte string of the appropriate length is a valid seed input.
The signing library hashes and prunes the seed-derived scalar and derives the
public key internally. Import does not interpret a seed as an encoded point
or require primality tests. Seed validity does not establish that a caller
chose unpredictable secret material.

`SoftwarePublicKey::validate` and Edwards signature verification share the
same public-key constructors:

- Ed25519 uses Dalek checked decoding, `VerifyingKey::is_weak()` rejection,
  and a compressed-point round trip to require canonical encoding.
  Signature verification uses `VerifyingKey::verify_strict`, rejecting
  small-order public keys and signature R points as well as invalid scalar
  encodings and equations. This is Dalek's strict verification policy;
  it does not add a separate full subgroup-membership test for Ed25519.
- Ed448 uses the dependency's checked point decoder, which checks the curve
  equation and prime-order subgroup, and its verifying-key constructor rejects
  the identity. A compressed-point round trip rejects noncanonical field
  encodings and unused bits. Signature R points receive the same checked
  decoding, canonical encoding, and identity checks before library verification.

These are public-point and signature checks. Private-seed acceptance and
serialization are independent. The shared implementation serves the software
slot and the virtual devices wherever they expose these algorithms; consumers
retain their supported algorithm sets, authorization, and protocol encoding.

## Sources and assurance boundaries

[RFC 8032 sections 5.1.3 and 5.2.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3)
specify point decoding; sections 5.1.5 and
[5.2.5](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.2.5) specify seed
expansion and scalar pruning. Sections 5.1.7 and 5.2.7 specify verification.
The RFC permits cofactored verification; the stricter weak-key/subgroup policy
above is an explicit library/application choice, not a claim that every check
is mandated by the RFC or that the software is a FIPS-validated module.

[Dalek's verifying-key documentation](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html)
explains `is_weak` and `verify_strict`. Ed448 uses the pinned
[`ed448-goldilocks` implementation](https://docs.rs/ed448-goldilocks/0.14.0-pre.15/ed448_goldilocks/struct.VerifyingKey.html),
including checked `CompressedEdwardsY::decompress` and `VerifyingKey::from_bytes`.
No independent curve arithmetic is implemented by these adapters.

## Verification

Regression tests cover valid zero/0xff seeds for both algorithms, identity and
small-order public keys, Ed448 mixed-order points, noncanonical public and
signature encodings, and an Ed25519 signature with low-order R that ordinary
verification accepts but strict verification rejects. RFC 8032 and Wycheproof
known-answer tests cover interoperable signatures and invalid inputs.
