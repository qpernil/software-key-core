# software-key-core

`software-key-core` provides protocol-neutral software key operations shared by
security-token providers and device emulators.

The crate owns reusable key generation, public-key projection, signing,
verification, raw key agreement, and narrowly scoped algorithm profiles. It
does not own protocol identifiers, PKCS #11 types, device authorization,
persistence, transport framing, or protocol-specific error mapping.

The local consumers intentionally use dependency-by-path so each working
directory directly represents the code being built:

```text
software-key-core
├── ../pkcs11rs
└── ../virtual-yubikey
```

## Development

Run the standalone test suite with:

```console
cargo test
```

The crate is not currently published. Consumers should continue using the
local path until repository and release metadata are established.
