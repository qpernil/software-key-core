# ML-KEM key import validation

`MlKemPrivateKey::from_expanded_private_key` accepts expanded FIPS 203
private decapsulation keys for ML-KEM-512, ML-KEM-768 and ML-KEM-1024.
The dependency first checks the encoding length, the embedded encapsulation
key's coefficient encoding and the stored hash H(ek). Before returning a key,
the shared import boundary performs one randomized pairwise consistency test:

1. Obtain 32 fresh bytes from operating-system randomness.
2. Encapsulate using the embedded public key and that randomness.
3. Decapsulate the resulting ciphertext using the candidate private key.
4. Compare the two 32-byte shared secrets in constant time; reject a mismatch.

The ML-KEM dependency uses arithmetic CBD sampling without secret-indexed
lookup tables, including during key generation and decapsulation.

ML-KEM decapsulation uses implicit rejection: it returns a secret even when
ciphertext verification fails. A successful call is therefore insufficient;
the two secrets must match. Inconsistent pairs return `InvalidExpandedPrivateKey`.
Unavailable randomness returns `RandomnessUnavailable` and does not produce a
key. Malformed encodings are rejected before requesting randomness.
Randomness and both shared-secret buffers use zeroizing storage, and a rejected
candidate releases its zeroizing private-key allocation. No secrets are logged.

The test is paid once at expanded private import. Cloning, ordinary
encapsulation and decapsulation do not repeat it. Seed import and generation
derive the complete pair internally. PKCS #8 import accepts the RFC 9935 seed,
expanded and combined representations. Expanded-only PKCS #8 import uses this
same checked boundary. When both representations are supplied, the complete
expanded bytes must match the seed expansion, including the rejection secret
`z`, which a successful pairwise test cannot validate. An optional outer public
key must match as well. Export prefers the retained seed, or uses expanded
encoding when no seed is available. Expanded import does not recreate a seed.

The PKCS #11 software token, virtual PIV, and virtual YubiHSM share
`from_components` for seed, expanded, and combined standalone imports.
`from_serialized` accepts exact-length raw seeds, expanded keys, and seed
followed by expanded key. `serialized` emits the retained seed or, when no
seed exists, the expanded key. Virtual-device persistence uses this raw form;
the software token uses the corresponding PKCS #8 representation. Validation
also applies when restoring expanded records.

## References

[FIPS 203 section 7.1](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
describes an optional imported-key-pair check; step 4 is the encapsulation /
decapsulation consistency test implemented here. Sections 7.2 and 7.3 specify
the encapsulation-key and decapsulation-key input checks. The pairwise test is
an explicit import policy, rather than a claim that every importing application
must perform it. It detects inconsistent components but does not prove proper
key generation, randomness quality or FIPS module validation.

[RFC 9935 sections 6–8](https://www.rfc-editor.org/rfc/rfc9935.html#section-6)
standardize seed, expanded and combined private-key representations and discuss
import consistency. The shared API retains expanded-key compatibility while
preferring seed representations for generation and persistence.

## Regression coverage

All three parameter sets accept valid expanded keys, preserve their public and
expanded encodings, and complete independent encapsulation/decapsulation tests.
A candidate combining a valid private vector with another key's public vector
and matching public hash is rejected. Additional cases cover noncanonical
public coefficients with a recomputed valid hash, corrupted hashes, wrong
lengths and failure after partial random-buffer initialization.

The PKCS #11 consumer tests the same valid/mismatched cases through CKA_VALUE
import for all three parameter sets. It maps inconsistent keys to
CKR_ATTRIBUTE_VALUE_INVALID and unavailable randomness to CKR_RANDOM_NO_RNG.

Independent RFC 9935 Appendix C fixtures cover every standard representation
for all parameter sets and all four published bad-key examples.
