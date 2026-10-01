# Wycheproof fixture provenance

Pinned upstream: https://github.com/C2SP/wycheproof/tree/0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45/testvectors_v1

`manifest.json` records the SHA-256 of each complete source JSON, original case
count, and retained count. `LICENSE` is the upstream Apache-2.0 license.
All source cases are retained except ECDH container cases outside the raw SEC1
API. ECDH selection accepts strict DER SPKI with the same algorithm identifier
as the group's normal named-curve case, zero unused BIT STRING bits, and no
trailing bytes. The source `public` value remains present; `publicSec1` contains
the extracted point. Expected values and result classifications are unchanged.

Compressed JSON uses no whitespace and gzip timestamp zero. SHAKE-ECDSA,
unsupported curves, SHA-512/224 and SHA-512/256, RSA parameter/miscellaneous
corpora and 8192-bit RSA are outside the exposed mechanism/key-size profile.
See [coverage and interpretation](../../../docs/known-answer-tests.md).
