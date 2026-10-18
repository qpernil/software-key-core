# RSA creation and validation

`rsa_keys::RsaKey` is the common private-key creation boundary. Its private
fields prevent a consumer from inserting a raw RustCrypto private key into
`SoftwareSigningKey::Rsa`. Generation, prime import, component import (including
factor recovery), and PKCS#8 import all normalize the private exponent, derive
CRT parameters, validate key quality and run a pairwise test before returning.
Clones share immutable key state and the validation result. A key is not
revalidated by signing, decryption, metadata access or cloning.

Protocol adapters retain authorization, supported sizes, declared algorithm
matching and allowed exponents. The common quality checks support sizes
from 512 through 16384 bits, including intermediate sizes. Odd legacy sizes
use floor/ceil half-width factors; NIST acceptance separately requires an even
modulus length. These implementation
work bounds do not enable new protocol algorithms. `check_nist_acceptance`
separately checks the SP 800-56B minimum size and exponent policy. Applying
quality checks to a legacy key does not make its size or exponent acceptable
under that policy.

## Private keys

The normalized prime-factor representation follows
[SP 800-56B Rev. 2 §6.4.1.2.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf#page=59),
incorporating §6.4.1.2.1: check the modulus, factor ranges and separation,
coprimality, factor primality, and private-exponent bounds and congruence.
The exponent-creation-unknown form is described in §6.4.1.4.2.
The pairwise test comes from §6.4.1.1: `m = (m^e)^d mod n`, with `m = 2`.
It uses the library's blinded, fault-checked private operation.

Primality testing uses independently sampled random Miller–Rabin bases
([FIPS 186-5 §B.3.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf#page=66)).
The error bound sets the iteration count from the modulus's estimated security
strength (SP 800-56B Appendix D); legacy sizes receive at least 112-bit test
assurance. One extra round conservatively bounds the combined error of both
factor tests. This margin is an implementation choice, not an additional FIPS
test. Random-base sampling is bounded and fails closed if randomness fails.
Named secret working buffers use zeroizing storage.

Native prime import supplies only `p`, `q` and the public exponent. PKCS#8
import checks supplied modulus/private-exponent consistency using RustCrypto,
then normalizes the equivalent private exponent and discards supplied CRT
values. The library derives the CRT values actually used. This validates the
normalized prime-factor key; it does not claim to validate the original CRT
representation under §6.4.1.2.3. No redundant comparisons of discarded CRT
values are performed.

## Public-only keys

`rsa_keys::import_public` uses
[SP 800-89 §5.3.3](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-89.pdf#page=17),
referenced by SP 800-56B §6.4.2.2: check modulus/exponent shape, reject factors
below 752, and require evidence that the modulus is composite and not a power
of one prime. Enhanced Miller–Rabin follows FIPS 186-5 §B.3.2. At most five
rounds are attempted, as in OpenSSL's public validation; probable-prime results
never authorize acceptance. The small-factor product includes every odd prime
through 751. Protocol-specific size/exponent acceptance remains separate.
These are partial checks: they do not prove secure generation or possession
of a corresponding private key. Ordinary public-key projection and signature
verification do not repeat import validation.

## Trusted state and assurance limits

Explicit `restore_*` operations reconstruct trusted persisted state with the
library's structural/algebraic checks. They avoid a primality test on every
load and retain legacy state compatibility. Untrusted imports must not use
restoration as their admission boundary. `validate_for_import` validates a
restored handle when an old wrapped-object representation crosses a new
import boundary; an already validated immutable handle avoids duplicate work.

Local validation cannot establish generation provenance or entropy quality.
This implementation is not a FIPS-validated module. Module validation also
covers approved random generation, algorithm self-tests, integrity, lifecycle,
error handling and other requirements. The generic imported-key PCT exemption
in [FIPS 140-3 IG §10.3.A, Additional Comment 1](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf#page=116)
does not replace the separately selected SP 800-56B owner-assurance policy.

## Verification and timing

Tests cover published Wycheproof RSA keys, primes and prime powers, composite
factors accepted by ordinary algebraic checks, entropy failure, intermediate
and legacy sizes, CRT normalization, and the inability to construct a software
private key from a raw unchecked RSA key. Consumer suites exercise their own
wire formats, generation/import, operations and persistence.

Run `cargo run --locked --release --example rsa_validation_cost` for paired
before/after measurements. Generation uses the same cryptographic RNG seed
for both paths and asserts matching moduli. The baseline reproduces the
previous library construction, while the after path calls the shared API.
Both import paths use identical factors/moduli; private-operation timing
excludes creation. These are in-process timings, excluding transport and
persistence. Reports contain no private key material.
