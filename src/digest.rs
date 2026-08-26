//! Protocol-neutral digest, HMAC and key-derivation constructions.

use hmac::{Mac, SimpleHmac};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    pub const fn sha1() -> Self {
        Self::Sha1
    }
    pub const fn sha224() -> Self {
        Self::Sha224
    }
    pub const fn sha256() -> Self {
        Self::Sha256
    }
    pub const fn sha384() -> Self {
        Self::Sha384
    }
    pub const fn sha512() -> Self {
        Self::Sha512
    }
    pub const fn sha3_224() -> Self {
        Self::Sha3_224
    }
    pub const fn sha3_256() -> Self {
        Self::Sha3_256
    }
    pub const fn sha3_384() -> Self {
        Self::Sha3_384
    }
    pub const fn sha3_512() -> Self {
        Self::Sha3_512
    }

    pub const fn output_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    pub const fn size(self) -> usize {
        self.output_length()
    }

    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        macro_rules! digest {
            ($digest:ty) => {
                <$digest>::digest(message).to_vec()
            };
        }
        match self {
            Self::Sha1 => digest!(Sha1),
            Self::Sha224 => digest!(Sha224),
            Self::Sha256 => digest!(Sha256),
            Self::Sha384 => digest!(Sha384),
            Self::Sha512 => digest!(Sha512),
            Self::Sha3_224 => digest!(Sha3_224),
            Self::Sha3_256 => digest!(Sha3_256),
            Self::Sha3_384 => digest!(Sha3_384),
            Self::Sha3_512 => digest!(Sha3_512),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestConstructionError {
    InvalidPseudoRandomKey,
    OutputTooLong,
}

#[derive(Clone)]
pub enum HashContext {
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
}

impl HashContext {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            HashAlgorithm::Sha224 => Self::Sha224(Sha224::new()),
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha3_224 => Self::Sha3_224(Sha3_224::new()),
            HashAlgorithm::Sha3_256 => Self::Sha3_256(Sha3_256::new()),
            HashAlgorithm::Sha3_384 => Self::Sha3_384(Sha3_384::new()),
            HashAlgorithm::Sha3_512 => Self::Sha3_512(Sha3_512::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        macro_rules! update {
            ($state:expr) => {
                Digest::update($state, data)
            };
        }
        match self {
            Self::Sha1(state) => update!(state),
            Self::Sha224(state) => update!(state),
            Self::Sha256(state) => update!(state),
            Self::Sha384(state) => update!(state),
            Self::Sha512(state) => update!(state),
            Self::Sha3_224(state) => update!(state),
            Self::Sha3_256(state) => update!(state),
            Self::Sha3_384(state) => update!(state),
            Self::Sha3_512(state) => update!(state),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        macro_rules! finalize {
            ($state:expr) => {
                Digest::finalize($state).to_vec()
            };
        }
        match self {
            Self::Sha1(state) => finalize!(state),
            Self::Sha224(state) => finalize!(state),
            Self::Sha256(state) => finalize!(state),
            Self::Sha384(state) => finalize!(state),
            Self::Sha512(state) => finalize!(state),
            Self::Sha3_224(state) => finalize!(state),
            Self::Sha3_256(state) => finalize!(state),
            Self::Sha3_384(state) => finalize!(state),
            Self::Sha3_512(state) => finalize!(state),
        }
    }
}

pub fn hmac(
    algorithm: HashAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, DigestConstructionError> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = <SimpleHmac<$digest> as hmac::digest::KeyInit>::new_from_slice(key)
                .map_err(|_| DigestConstructionError::InvalidPseudoRandomKey)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algorithm {
        HashAlgorithm::Sha1 => calculate!(Sha1),
        HashAlgorithm::Sha224 => calculate!(Sha224),
        HashAlgorithm::Sha256 => calculate!(Sha256),
        HashAlgorithm::Sha384 => calculate!(Sha384),
        HashAlgorithm::Sha512 => calculate!(Sha512),
        HashAlgorithm::Sha3_224 => calculate!(Sha3_224),
        HashAlgorithm::Sha3_256 => calculate!(Sha3_256),
        HashAlgorithm::Sha3_384 => calculate!(Sha3_384),
        HashAlgorithm::Sha3_512 => calculate!(Sha3_512),
    }
}

pub fn mgf1(
    algorithm: HashAlgorithm,
    seed: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, DigestConstructionError> {
    let blocks = output_length.div_ceil(algorithm.output_length());
    if blocks
        .checked_sub(1)
        .is_some_and(|last_counter| u32::try_from(last_counter).is_err())
    {
        return Err(DigestConstructionError::OutputTooLong);
    }
    let mut output = Vec::with_capacity(output_length);
    for counter in 0..blocks {
        let mut input = Vec::with_capacity(seed.len().saturating_add(4));
        input.extend_from_slice(seed);
        input.extend_from_slice(&(counter as u32).to_be_bytes());
        output.extend_from_slice(&algorithm.digest(&input));
    }
    output.truncate(output_length);
    Ok(output)
}

pub fn x963_kdf(
    algorithm: HashAlgorithm,
    secret: &[u8],
    shared_data: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, DigestConstructionError> {
    let blocks = output_length.div_ceil(algorithm.output_length());
    if output_length == 0 || blocks > u32::MAX as usize {
        return Err(DigestConstructionError::OutputTooLong);
    }
    let input_length = secret
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(shared_data.len()))
        .ok_or(DigestConstructionError::OutputTooLong)?;
    let mut output = Zeroizing::new(Vec::with_capacity(output_length));
    for counter in 1..=blocks {
        let mut input = Zeroizing::new(Vec::with_capacity(input_length));
        input.extend_from_slice(secret);
        input.extend_from_slice(&(counter as u32).to_be_bytes());
        input.extend_from_slice(shared_data);
        let block = Zeroizing::new(algorithm.digest(&input));
        let remaining = output_length - output.len();
        output.extend_from_slice(&block[..remaining.min(block.len())]);
    }
    Ok(output)
}

pub fn hkdf(
    algorithm: HashAlgorithm,
    extract: bool,
    expand: bool,
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, DigestConstructionError> {
    macro_rules! derive {
        ($hash:ty) => {{
            if extract {
                let (mut prk, hkdf) = hkdf::SimpleHkdf::<$hash>::extract(salt, input_key_material);
                if expand {
                    prk.zeroize();
                    let mut output = Zeroizing::new(vec![0; output_length]);
                    hkdf.expand(info, &mut output)
                        .map_err(|_| DigestConstructionError::OutputTooLong)?;
                    Ok(output)
                } else {
                    let output = Zeroizing::new(prk.to_vec());
                    prk.zeroize();
                    Ok(output)
                }
            } else {
                let hkdf = hkdf::SimpleHkdf::<$hash>::from_prk(input_key_material)
                    .map_err(|_| DigestConstructionError::InvalidPseudoRandomKey)?;
                let mut output = Zeroizing::new(vec![0; output_length]);
                hkdf.expand(info, &mut output)
                    .map_err(|_| DigestConstructionError::OutputTooLong)?;
                Ok(output)
            }
        }};
    }
    match algorithm {
        HashAlgorithm::Sha1 => derive!(Sha1),
        HashAlgorithm::Sha224 => derive!(Sha224),
        HashAlgorithm::Sha256 => derive!(Sha256),
        HashAlgorithm::Sha384 => derive!(Sha384),
        HashAlgorithm::Sha512 => derive!(Sha512),
        HashAlgorithm::Sha3_224 => derive!(Sha3_224),
        HashAlgorithm::Sha3_256 => derive!(Sha3_256),
        HashAlgorithm::Sha3_384 => derive!(Sha3_384),
        HashAlgorithm::Sha3_512 => derive!(Sha3_512),
    }
}

pub fn pbkdf2_hmac(
    algorithm: HashAlgorithm,
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, DigestConstructionError> {
    let mut output = Zeroizing::new(vec![0; output_length]);
    macro_rules! derive {
        ($hash:ty) => {
            pbkdf2::pbkdf2::<SimpleHmac<$hash>>(password, salt, rounds, output.as_mut())
                .map_err(|_| DigestConstructionError::InvalidPseudoRandomKey)
        };
    }
    match algorithm {
        HashAlgorithm::Sha1 => derive!(Sha1),
        HashAlgorithm::Sha224 => derive!(Sha224),
        HashAlgorithm::Sha256 => derive!(Sha256),
        HashAlgorithm::Sha384 => derive!(Sha384),
        HashAlgorithm::Sha512 => derive!(Sha512),
        HashAlgorithm::Sha3_224 => derive!(Sha3_224),
        HashAlgorithm::Sha3_256 => derive!(Sha3_256),
        HashAlgorithm::Sha3_384 => derive!(Sha3_384),
        HashAlgorithm::Sha3_512 => derive!(Sha3_512),
    }?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869_case_one() {
        let output = hkdf(
            HashAlgorithm::Sha256,
            true,
            true,
            &[0x0b; 22],
            Some(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            ]),
            &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
            42,
        )
        .unwrap();
        assert_eq!(
            output.as_slice(),
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn hmac_and_mgf1_are_stable() {
        assert_eq!(
            hmac(HashAlgorithm::Sha256, b"key", b"data").unwrap().len(),
            32
        );
        assert_eq!(
            mgf1(HashAlgorithm::Sha3_384, b"seed", 81).unwrap().len(),
            81
        );
        assert_eq!(
            x963_kdf(HashAlgorithm::Sha224, b"secret", b"info", 33)
                .unwrap()
                .len(),
            33
        );
    }

    #[test]
    fn pbkdf2_matches_rfc_6070_case_one() {
        assert_eq!(
            pbkdf2_hmac(HashAlgorithm::Sha1, b"password", b"salt", 1, 20)
                .unwrap()
                .as_slice(),
            &[
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
            ]
        );
    }
}
