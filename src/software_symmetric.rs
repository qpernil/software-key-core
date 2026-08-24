//! Protocol-neutral AES operations for software-held symmetric keys.

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Aes192, Aes256,
};
use ccm::{
    aead::{generic_array::GenericArray as AeadArray, Aead},
    consts::{U13, U16},
    Ccm,
};
use cmac::{Cmac, Mac};

pub const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSymmetricError {
    InvalidKeyLength,
    InvalidDataLength,
    InvalidIvLength,
    AuthenticationFailed,
}

pub fn wrap_aes_kwp(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SoftwareSymmetricError> {
    let output_length = (plaintext.len().div_ceil(8) + 1) * 8;
    let mut output = vec![0; output_length];
    let result = match key.len() {
        16 => <aes_kw::KwpAes128 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .wrap_key(plaintext, &mut output),
        24 => <aes_kw::KwpAes192 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .wrap_key(plaintext, &mut output),
        32 => <aes_kw::KwpAes256 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .wrap_key(plaintext, &mut output),
        _ => return Err(SoftwareSymmetricError::InvalidKeyLength),
    }
    .map_err(|_| SoftwareSymmetricError::InvalidDataLength)?;
    Ok(result.to_vec())
}

pub fn unwrap_aes_kwp(key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, SoftwareSymmetricError> {
    let output_length = wrapped
        .len()
        .checked_sub(8)
        .ok_or(SoftwareSymmetricError::InvalidDataLength)?;
    let mut output = vec![0; output_length];
    let result = match key.len() {
        16 => <aes_kw::KwpAes128 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .unwrap_key(wrapped, &mut output),
        24 => <aes_kw::KwpAes192 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .unwrap_key(wrapped, &mut output),
        32 => <aes_kw::KwpAes256 as aes_kw::KeyInit>::new_from_slice(key)
            .unwrap()
            .unwrap_key(wrapped, &mut output),
        _ => return Err(SoftwareSymmetricError::InvalidKeyLength),
    }
    .map_err(|_| SoftwareSymmetricError::AuthenticationFailed)?;
    Ok(result.to_vec())
}

pub const AES_CCM_NONCE_SIZE: usize = 13;
pub const AES_CCM_TAG_SIZE: usize = 16;
pub const YUBICO_OTP_TAG_SIZE: usize = 8;

pub fn encrypt_yubico_otp_aead(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if nonce.len() != AES_CCM_NONCE_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    let nonce = AeadArray::from_slice(nonce);
    macro_rules! encrypt {
        ($cipher:ty) => {
            Ccm::<$cipher, ccm::consts::U8, U13>::new_from_slice(key)
                .unwrap()
                .encrypt(nonce, plaintext)
                .map_err(|_| SoftwareSymmetricError::AuthenticationFailed)
        };
    }
    match key.len() {
        16 => encrypt!(Aes128),
        24 => encrypt!(Aes192),
        32 => encrypt!(Aes256),
        _ => Err(SoftwareSymmetricError::InvalidKeyLength),
    }
}

pub fn decrypt_yubico_otp_aead(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if nonce.len() != AES_CCM_NONCE_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    if ciphertext_and_tag.len() < YUBICO_OTP_TAG_SIZE {
        return Err(SoftwareSymmetricError::InvalidDataLength);
    }
    let nonce = AeadArray::from_slice(nonce);
    macro_rules! decrypt {
        ($cipher:ty) => {
            Ccm::<$cipher, ccm::consts::U8, U13>::new_from_slice(key)
                .unwrap()
                .decrypt(nonce, ciphertext_and_tag)
                .map_err(|_| SoftwareSymmetricError::AuthenticationFailed)
        };
    }
    match key.len() {
        16 => decrypt!(Aes128),
        24 => decrypt!(Aes192),
        32 => decrypt!(Aes256),
        _ => Err(SoftwareSymmetricError::InvalidKeyLength),
    }
}

pub fn encrypt_aes_ccm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if nonce.len() != AES_CCM_NONCE_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    let nonce = AeadArray::from_slice(nonce);
    match key.len() {
        16 => Ccm::<Aes128, U16, U13>::new_from_slice(key)
            .unwrap()
            .encrypt(nonce, plaintext)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        24 => Ccm::<Aes192, U16, U13>::new_from_slice(key)
            .unwrap()
            .encrypt(nonce, plaintext)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        32 => Ccm::<Aes256, U16, U13>::new_from_slice(key)
            .unwrap()
            .encrypt(nonce, plaintext)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        _ => Err(SoftwareSymmetricError::InvalidKeyLength),
    }
}

pub fn decrypt_aes_ccm(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if nonce.len() != AES_CCM_NONCE_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    if ciphertext_and_tag.len() < AES_CCM_TAG_SIZE {
        return Err(SoftwareSymmetricError::InvalidDataLength);
    }
    let nonce = AeadArray::from_slice(nonce);
    match key.len() {
        16 => Ccm::<Aes128, U16, U13>::new_from_slice(key)
            .unwrap()
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        24 => Ccm::<Aes192, U16, U13>::new_from_slice(key)
            .unwrap()
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        32 => Ccm::<Aes256, U16, U13>::new_from_slice(key)
            .unwrap()
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|_| SoftwareSymmetricError::AuthenticationFailed),
        _ => Err(SoftwareSymmetricError::InvalidKeyLength),
    }
}

enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesCipher {
    fn new(key: &[u8]) -> Result<Self, SoftwareSymmetricError> {
        match key.len() {
            16 => Ok(Self::Aes128(Aes128::new_from_slice(key).unwrap())),
            24 => Ok(Self::Aes192(Aes192::new_from_slice(key).unwrap())),
            32 => Ok(Self::Aes256(Aes256::new_from_slice(key).unwrap())),
            _ => Err(SoftwareSymmetricError::InvalidKeyLength),
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, aes::cipher::consts::U16>) {
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes192(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, aes::cipher::consts::U16>) {
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(block),
            Self::Aes192(cipher) => cipher.decrypt_block(block),
            Self::Aes256(cipher) => cipher.decrypt_block(block),
        }
    }
}

/// Calculate AES-CMAC with a 128, 192, or 256-bit AES key.
pub fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], SoftwareSymmetricError> {
    macro_rules! calculate {
        ($cipher:ty) => {{
            let mut mac = <Cmac<$cipher> as Mac>::new_from_slice(key)
                .map_err(|_| SoftwareSymmetricError::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().into())
        }};
    }

    match key.len() {
        16 => calculate!(Aes128),
        24 => calculate!(Aes192),
        32 => calculate!(Aes256),
        _ => Err(SoftwareSymmetricError::InvalidKeyLength),
    }
}

/// Encrypt one AES block with a 128, 192, or 256-bit AES key.
pub fn encrypt_aes_block(
    key: &[u8],
    input: &[u8; AES_BLOCK_SIZE],
) -> Result<[u8; AES_BLOCK_SIZE], SoftwareSymmetricError> {
    let cipher = AesCipher::new(key)?;
    let mut block = GenericArray::from(*input);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

/// Decrypt one AES block with a 128, 192, or 256-bit AES key.
pub fn decrypt_aes_block(
    key: &[u8],
    input: &[u8; AES_BLOCK_SIZE],
) -> Result<[u8; AES_BLOCK_SIZE], SoftwareSymmetricError> {
    let cipher = AesCipher::new(key)?;
    let mut block = GenericArray::from(*input);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

pub fn encrypt_aes_ecb(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SoftwareSymmetricError> {
    transform_ecb(key, plaintext, true)
}

pub fn decrypt_aes_ecb(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SoftwareSymmetricError> {
    transform_ecb(key, ciphertext, false)
}

fn transform_ecb(
    key: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if input.len() % AES_BLOCK_SIZE != 0 {
        return Err(SoftwareSymmetricError::InvalidDataLength);
    }
    let cipher = AesCipher::new(key)?;
    let mut output = input.to_vec();
    for chunk in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        if encrypt {
            cipher.encrypt_block(block);
        } else {
            cipher.decrypt_block(block);
        }
    }
    Ok(output)
}

pub fn encrypt_aes_cbc(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
        return Err(SoftwareSymmetricError::InvalidDataLength);
    }
    let cipher = AesCipher::new(key)?;
    let mut previous: [u8; AES_BLOCK_SIZE] = iv.try_into().unwrap();
    let mut output = plaintext.to_vec();
    for chunk in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        for (byte, previous) in chunk.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        previous.copy_from_slice(chunk);
    }
    Ok(output)
}

pub fn decrypt_aes_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SoftwareSymmetricError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(SoftwareSymmetricError::InvalidIvLength);
    }
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(SoftwareSymmetricError::InvalidDataLength);
    }
    let cipher = AesCipher::new(key)?;
    let mut previous: [u8; AES_BLOCK_SIZE] = iv.try_into().unwrap();
    let mut output = ciphertext.to_vec();
    for chunk in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        let current: [u8; AES_BLOCK_SIZE] = chunk.try_into().unwrap();
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (byte, previous) in chunk.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        previous = current;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ecb_matches_fips_197_vectors_for_every_key_size() {
        let plaintext = hex("00112233445566778899aabbccddeeff");
        for (key, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key = hex(key);
            let ciphertext = encrypt_aes_ecb(&key, &plaintext).unwrap();
            assert_eq!(ciphertext, hex(expected));
            assert_eq!(decrypt_aes_ecb(&key, &ciphertext).unwrap(), plaintext);
            let block: [u8; AES_BLOCK_SIZE] = plaintext.as_slice().try_into().unwrap();
            let encrypted = encrypt_aes_block(&key, &block).unwrap();
            assert_eq!(encrypted.as_slice(), hex(expected));
            assert_eq!(decrypt_aes_block(&key, &encrypted).unwrap(), block);
        }
    }

    #[test]
    fn aes_cmac_matches_nist_sp_800_38b() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let message = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            aes_cmac(&key, &message).unwrap().as_slice(),
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
    }

    #[test]
    fn aes_cbc_matches_nist_sp_800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = hex(concat!(
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7"
        ));
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext).unwrap();
        assert_eq!(ciphertext, expected);
        assert_eq!(decrypt_aes_cbc(&key, &iv, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn aes_ccm_round_trips_and_authenticates_for_every_key_size() {
        let nonce = [0x33; AES_CCM_NONCE_SIZE];
        for key in [vec![1; 16], vec![2; 24], vec![3; 32]] {
            let mut encrypted = encrypt_aes_ccm(&key, &nonce, b"wrapped payload").unwrap();
            assert_eq!(encrypted.len(), 15 + AES_CCM_TAG_SIZE);
            assert_eq!(
                decrypt_aes_ccm(&key, &nonce, &encrypted).unwrap(),
                b"wrapped payload"
            );
            encrypted[0] ^= 1;
            assert_eq!(
                decrypt_aes_ccm(&key, &nonce, &encrypted),
                Err(SoftwareSymmetricError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn aes_kwp_round_trips_arbitrary_lengths_for_every_key_size() {
        for key in [vec![1; 16], vec![2; 24], vec![3; 32]] {
            for plaintext in [b"one".as_slice(), b"exactly-16-bytes".as_slice()] {
                let mut wrapped = wrap_aes_kwp(&key, plaintext).unwrap();
                assert_eq!(unwrap_aes_kwp(&key, &wrapped).unwrap(), plaintext);
                wrapped[0] ^= 1;
                assert_eq!(
                    unwrap_aes_kwp(&key, &wrapped),
                    Err(SoftwareSymmetricError::AuthenticationFailed)
                );
            }
        }
    }

    #[test]
    fn yubico_otp_aead_uses_eight_byte_tags() {
        let nonce = [0x42; AES_CCM_NONCE_SIZE];
        for key in [vec![1; 16], vec![2; 24], vec![3; 32]] {
            let encrypted = encrypt_yubico_otp_aead(&key, &nonce, &[0x55; 22]).unwrap();
            assert_eq!(encrypted.len(), 22 + YUBICO_OTP_TAG_SIZE);
            assert_eq!(
                decrypt_yubico_otp_aead(&key, &nonce, &encrypted).unwrap(),
                [0x55; 22]
            );
        }
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
