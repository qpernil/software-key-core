# Public PQC private-key fixtures

These DER files decode the public PEM examples from RFC 9881 Appendix C.1/C.4
(ML-DSA) and RFC 9935 Appendix C.1/C.4.1 (ML-KEM). They are test data, not secrets.
The `seed`, `expanded` and `both` fixtures describe the same key for each
parameter set. Every `bad` fixture must be rejected, including the inconsistent
ML-DSA `tr`/`t0` cases and the ML-KEM mismatch affecting only `z`.

Sources:
- https://www.rfc-editor.org/rfc/rfc9881.html#appendix-C
- https://www.rfc-editor.org/rfc/rfc9935.html#appendix-C

Copyright (c) IETF Trust and the persons identified as the document authors.
See https://trustee.ietf.org/license-info for the applicable IETF document terms.
