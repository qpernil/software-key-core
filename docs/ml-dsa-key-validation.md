# ML-DSA expanded key import validation

The shared `MlDsaPrivateKey` boundary accepts 32-byte generation seeds and the
expanded FIPS 204 private encodings for ML-DSA-44 (2,560 bytes), ML-DSA-65
(4,032 bytes), and ML-DSA-87 (4,896 bytes). A seed derives a complete pair;
expanded import validates independently supplied private components.

Before any signing, `software-key-core` validates expanded material using the
public API of the pinned minimal ML-DSA stack-usage PR:

1. Checks the exact length and the packed `s1`/`s2` coefficient ranges. Reserved
   encodings return an error before the legacy decoder's assertions can run.
2. Computes `t = A*s1 + s2` with application-side FIPS 204 NTT/ExpandA
   operations and the released `module-lattice` field arithmetic. Secret
   validation vectors use zeroizing storage; matrix sampling uses public data.
3. Requires the supplied `t0` to equal `Power2Round(t)`'s low part.
4. Uses the dependency's public API to derive the public key from `rho` and
   the high part `t1`, and checks that its hash equals the supplied `tr`,
   using constant-time comparisons.

The `signatures` dependency contains only the matrix stack-usage fix; it has
no downstream import-validation API. Its expanded decoder is called only after
coefficient and `t0` validation.

The shared boundary then signs a fixed test message and verifies it with the
derived public key. The validated private holder and cached public key are
shared through `Arc`; normal signing and cloning do not repeat import checks.
The dependency zeroizes private state when its last owner is dropped.

The signing randomizer seed `K` is independent material, not a checksum. These
checks cannot prove that `K` or the other components came from an approved RNG.
They establish encoding, algebraic and operational consistency, not proper key
generation or FIPS module certification.

## Encodings and seed availability

[RFC 9881 section 6](https://www.rfc-editor.org/rfc/rfc9881.html#section-6)
defines PKCS #8 seed, expanded and combined representations. All three are
accepted. If both are present, the entire expanded encoding must equal the seed
expansion, including `K`. An optional outer public key must also match. DER must
use the correct algorithm OID and absent parameters. Export prefers the seed
when retained and otherwise writes the expanded representation. `seed()` returns
`None` after expanded-only import; it never fabricates a replacement seed.

[RFC 9881 section 8.2](https://www.rfc-editor.org/rfc/rfc9881.html#section-8.2)
recommends consistency testing when both forms are present and requires rejection
when that test finds a mismatch. Appendix C.4 describes the inconsistent `tr`
and `t0` cases rejected here. The algebraic checks reuse the relationships in
[FIPS 204 Algorithms 6, 22 and 25](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
and the operational test uses Algorithms 7–8. They are the project's explicit
expanded-import policy; FIPS 204 does not itself mandate all of these extra
import checks.

## Protocol policy and tests

The PKCS #11 software token, virtual PIV, and virtual YubiHSM use the same
`from_components` validation for seed, expanded, and combined standalone keys.
`from_serialized` accepts an exact-length raw seed, expanded key, or seed
followed by its expanded key. `serialized` preserves a known seed and otherwise
returns the expanded encoding. Virtual-device persistence uses that canonical
raw representation; the software token uses the equivalent PKCS #8 choice.
Protocol adapters retain authorization, framing, and error mapping.
Concrete hybrid KEMs retain a single 32-byte seed deriving both components;
separately supplied expanded component keys are not an accepted hybrid format.

Tests cover all ML-DSA parameter sets: RFC 9881 seed/expanded/combined fixtures,
all three published invalid examples, malformed coefficients and lengths,
redundant-material mismatches, pure and HashML-DSA signing, seedless persistence,
and unoptimized import on a 512 KiB caller stack. This is a tested configuration;
callers need headroom for their own frames. The PKCS #11 adapter separately
checks its import attributes and persistence round trips for every variant.
