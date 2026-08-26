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
use ghash::{universal_hash::UniversalHash, GHash};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSymmetricError {
    InvalidKeyLength,
    InvalidDataLength,
    InvalidIvLength,
    AuthenticationFailed,
}

/// Failure from AES-GCM implemented over an arbitrary AES block encryptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AesGcmError<E> {
    InvalidIvLength,
    InvalidTagLength,
    InputTooLong,
    CiphertextTooShort,
    InvalidBlockOutput,
    AuthenticationFailed,
    EncryptBlocks(E),
}

/// Failure from an AES construction implemented over a caller-supplied block
/// encryptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AesBlockModeError<E> {
    InvalidCounterBits,
    InputTooLong,
    InvalidBlockOutput,
    EncryptBlocks(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesCcmOperation {
    EncryptBlocks,
    CbcMac,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AesCcmError<E> {
    InvalidNonceLength,
    InvalidTagLength,
    InvalidDataLength,
    InputTooLong,
    InvalidBlockOutput,
    AuthenticationFailed,
    Crypt(E),
}

fn aes_cmac_double(mut block: [u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let carry = block[0] >> 7;
    for index in 0..AES_BLOCK_SIZE - 1 {
        block[index] = (block[index] << 1) | (block[index + 1] >> 7);
    }
    block[AES_BLOCK_SIZE - 1] <<= 1;
    block[AES_BLOCK_SIZE - 1] ^= 0x87 & 0u8.wrapping_sub(carry);
    block
}

/// Calculate AES-CMAC using a caller-supplied AES ECB block encryptor.
pub fn aes_cmac_with<E>(
    data: &[u8],
    mut encrypt_blocks: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<[u8; AES_BLOCK_SIZE], AesBlockModeError<E>> {
    let encrypted_zero =
        encrypt_blocks(&[0; AES_BLOCK_SIZE]).map_err(AesBlockModeError::EncryptBlocks)?;
    let subkey = encrypted_zero
        .as_slice()
        .try_into()
        .map(aes_cmac_double)
        .map_err(|_| AesBlockModeError::InvalidBlockOutput)?;
    let complete = !data.is_empty() && data.len().is_multiple_of(AES_BLOCK_SIZE);
    let last_subkey = if complete {
        subkey
    } else {
        aes_cmac_double(subkey)
    };
    let block_count = std::cmp::max(1, data.len().div_ceil(AES_BLOCK_SIZE));
    let mut state = [0; AES_BLOCK_SIZE];

    for block_index in 0..block_count {
        let start = block_index * AES_BLOCK_SIZE;
        let available = data.len().saturating_sub(start).min(AES_BLOCK_SIZE);
        let mut block = [0; AES_BLOCK_SIZE];
        block[..available].copy_from_slice(&data[start..start + available]);
        if block_index + 1 == block_count {
            if !complete {
                block[available] = 0x80;
            }
            for (value, subkey) in block.iter_mut().zip(last_subkey) {
                *value ^= subkey;
            }
        }
        for (value, previous) in block.iter_mut().zip(state) {
            *value ^= previous;
        }
        let encrypted = encrypt_blocks(&block).map_err(AesBlockModeError::EncryptBlocks)?;
        state = encrypted
            .as_slice()
            .try_into()
            .map_err(|_| AesBlockModeError::InvalidBlockOutput)?;
    }
    Ok(state)
}

/// Apply the PKCS #11 AES-CTR construction using a caller-supplied AES ECB
/// block encryptor.
pub fn aes_ctr_with<E>(
    counter_bits: usize,
    counter_block: [u8; AES_BLOCK_SIZE],
    input: &[u8],
    mut encrypt_blocks: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AesBlockModeError<E>> {
    if !(1..=AES_BLOCK_SIZE * 8).contains(&counter_bits) {
        return Err(AesBlockModeError::InvalidCounterBits);
    }
    let block_count = input.len().div_ceil(AES_BLOCK_SIZE);
    let counter_capacity = block_count
        .checked_mul(AES_BLOCK_SIZE)
        .ok_or(AesBlockModeError::InputTooLong)?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    let initial = u128::from_be_bytes(counter_block);
    let mask = if counter_bits == 128 {
        u128::MAX
    } else {
        (1u128 << counter_bits) - 1
    };
    let fixed = initial & !mask;
    let initial_counter = initial & mask;
    for offset in 0..block_count {
        let offset = offset as u128;
        let counter = fixed | (initial_counter.wrapping_add(offset) & mask);
        counter_blocks.extend_from_slice(&counter.to_be_bytes());
    }
    let key_stream = encrypt_blocks(&counter_blocks).map_err(AesBlockModeError::EncryptBlocks)?;
    if key_stream.len() != counter_blocks.len() {
        return Err(AesBlockModeError::InvalidBlockOutput);
    }
    Ok(input
        .iter()
        .zip(key_stream)
        .map(|(input, key_stream)| input ^ key_stream)
        .collect())
}

/// Apply general AES-CCM using caller-supplied AES block encryption and CBC-MAC
/// operations.
pub fn aes_ccm_with<E>(
    data_length: usize,
    nonce: &[u8],
    aad: &[u8],
    tag_length: usize,
    input: &[u8],
    encrypting: bool,
    mut crypt: impl FnMut(AesCcmOperation, &[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AesCcmError<E>> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(AesCcmError::InvalidNonceLength);
    }
    if !matches!(tag_length, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        return Err(AesCcmError::InvalidTagLength);
    }
    let length_bytes = 15 - nonce.len();
    if length_bytes < 8 && data_length as u128 >= 1u128 << (length_bytes * 8) {
        return Err(AesCcmError::InputTooLong);
    }
    if aad.len() > u32::MAX as usize {
        return Err(AesCcmError::InputTooLong);
    }
    let expected_input = if encrypting {
        data_length
    } else {
        data_length
            .checked_add(tag_length)
            .ok_or(AesCcmError::InputTooLong)?
    };
    if input.len() != expected_input {
        return Err(AesCcmError::InvalidDataLength);
    }
    let (payload, supplied_tag) = if encrypting {
        (input, None)
    } else {
        (&input[..data_length], Some(&input[data_length..]))
    };

    let block_count = data_length.div_ceil(AES_BLOCK_SIZE);
    let counter_capacity = block_count
        .checked_add(1)
        .and_then(|blocks| blocks.checked_mul(AES_BLOCK_SIZE))
        .ok_or(AesCcmError::InputTooLong)?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    for counter in 0..=block_count {
        let mut block = [0; AES_BLOCK_SIZE];
        block[0] = (length_bytes - 1) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        let encoded = (counter as u64).to_be_bytes();
        block[AES_BLOCK_SIZE - length_bytes..]
            .copy_from_slice(&encoded[encoded.len() - length_bytes..]);
        counter_blocks.extend_from_slice(&block);
    }
    let key_stream =
        crypt(AesCcmOperation::EncryptBlocks, &counter_blocks).map_err(AesCcmError::Crypt)?;
    if key_stream.len() != counter_blocks.len() {
        return Err(AesCcmError::InvalidBlockOutput);
    }
    let mut transformed = Vec::with_capacity(payload.len());
    for (block, key_stream) in payload
        .chunks(AES_BLOCK_SIZE)
        .zip(key_stream[AES_BLOCK_SIZE..].chunks(AES_BLOCK_SIZE))
    {
        transformed.extend(
            block
                .iter()
                .zip(key_stream)
                .map(|(input, key_stream)| input ^ key_stream),
        );
    }
    let plaintext = if encrypting {
        payload
    } else {
        transformed.as_slice()
    };

    let mut mac_input = Zeroizing::new(Vec::new());
    let mut b0 = [0; AES_BLOCK_SIZE];
    b0[0] = u8::from(!aad.is_empty()) << 6
        | (((tag_length - 2) / 2) as u8) << 3
        | (length_bytes - 1) as u8;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let encoded_length = (data_length as u64).to_be_bytes();
    b0[AES_BLOCK_SIZE - length_bytes..]
        .copy_from_slice(&encoded_length[encoded_length.len() - length_bytes..]);
    mac_input.extend_from_slice(&b0);
    if !aad.is_empty() {
        if aad.len() < 0xff00 {
            mac_input.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else {
            mac_input.extend_from_slice(&[0xff, 0xfe]);
            mac_input.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        }
        mac_input.extend_from_slice(aad);
        let padded_length = mac_input.len().next_multiple_of(AES_BLOCK_SIZE);
        mac_input.resize(padded_length, 0);
    }
    mac_input.extend_from_slice(plaintext);
    let padded_length = mac_input.len().next_multiple_of(AES_BLOCK_SIZE);
    mac_input.resize(padded_length, 0);
    let mac = crypt(AesCcmOperation::CbcMac, &mac_input).map_err(AesCcmError::Crypt)?;
    let mac: [u8; AES_BLOCK_SIZE] = mac
        .try_into()
        .map_err(|_| AesCcmError::InvalidBlockOutput)?;
    let tag = mac[..tag_length]
        .iter()
        .zip(&key_stream[..tag_length])
        .map(|(mac, mask)| mac ^ mask)
        .collect::<Vec<_>>();

    if let Some(supplied_tag) = supplied_tag {
        if !bool::from(tag.as_slice().ct_eq(supplied_tag)) {
            transformed.fill(0);
            return Err(AesCcmError::AuthenticationFailed);
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&tag);
        Ok(transformed)
    }
}

fn ghash(key: [u8; AES_BLOCK_SIZE], aad: &[u8], ciphertext: &[u8]) -> Option<[u8; AES_BLOCK_SIZE]> {
    let aad_bits = u64::try_from(aad.len().checked_mul(8)?).ok()?;
    let ciphertext_bits = u64::try_from(ciphertext.len().checked_mul(8)?).ok()?;
    let mut hash = GHash::new(&key.into());
    hash.update_padded(aad);
    hash.update_padded(ciphertext);
    let mut lengths = [0; AES_BLOCK_SIZE];
    lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    hash.update(&[lengths.into()]);
    Some(hash.finalize().into())
}

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    let value = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&value.to_be_bytes());
}

fn gcm_tag(full_tag: [u8; AES_BLOCK_SIZE], tag_bits: usize) -> Vec<u8> {
    let tag_length = tag_bits.div_ceil(8);
    let mut tag = full_tag[..tag_length].to_vec();
    if !tag_bits.is_multiple_of(8) {
        let mask = 0xff << (8 - tag_bits % 8);
        if let Some(last) = tag.last_mut() {
            *last &= mask;
        }
    }
    tag
}

/// Apply AES-GCM using a caller-supplied AES ECB block encryptor.
///
/// The callback receives one or more complete 16-byte blocks and must return
/// the encrypted blocks with exactly the same length. This permits the same
/// protocol-neutral GCM implementation to operate with software-held keys or
/// with keys whose only available primitive is a hardware ECB command.
pub fn aes_gcm_with<E>(
    iv: &[u8],
    aad: &[u8],
    tag_bits: usize,
    input: &[u8],
    encrypting: bool,
    mut encrypt_blocks: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, AesGcmError<E>> {
    if iv.is_empty() {
        return Err(AesGcmError::InvalidIvLength);
    }
    if tag_bits > AES_BLOCK_SIZE * 8 {
        return Err(AesGcmError::InvalidTagLength);
    }
    let tag_length = tag_bits.div_ceil(8);
    let (payload, supplied_tag) = if encrypting {
        (input, None)
    } else {
        if input.len() < tag_length {
            return Err(AesGcmError::CiphertextTooShort);
        }
        let split = input.len() - tag_length;
        (&input[..split], Some(&input[split..]))
    };
    let block_count = payload.len().div_ceil(AES_BLOCK_SIZE);
    if block_count > u32::MAX as usize - 2 {
        return Err(AesGcmError::InputTooLong);
    }

    let hash_subkey = encrypt_blocks(&[0; AES_BLOCK_SIZE]).map_err(AesGcmError::EncryptBlocks)?;
    let hash_subkey: [u8; AES_BLOCK_SIZE] = hash_subkey
        .as_slice()
        .try_into()
        .map_err(|_| AesGcmError::InvalidBlockOutput)?;
    let mut initial_counter = if iv.len() == 12 {
        let mut counter = [0; AES_BLOCK_SIZE];
        counter[..12].copy_from_slice(iv);
        counter[15] = 1;
        counter
    } else {
        ghash(hash_subkey, &[], iv).ok_or(AesGcmError::InputTooLong)?
    };

    let counter_capacity = (block_count + 1)
        .checked_mul(AES_BLOCK_SIZE)
        .ok_or(AesGcmError::InputTooLong)?;
    let mut counter_blocks = Vec::with_capacity(counter_capacity);
    counter_blocks.extend_from_slice(&initial_counter);
    for _ in 0..block_count {
        increment_gcm_counter(&mut initial_counter);
        counter_blocks.extend_from_slice(&initial_counter);
    }
    let encrypted_counters = encrypt_blocks(&counter_blocks).map_err(AesGcmError::EncryptBlocks)?;
    if encrypted_counters.len() != counter_blocks.len() {
        return Err(AesGcmError::InvalidBlockOutput);
    }
    let mut transformed = Vec::with_capacity(payload.len());
    for (block, key_stream) in payload
        .chunks(AES_BLOCK_SIZE)
        .zip(encrypted_counters[AES_BLOCK_SIZE..].chunks(AES_BLOCK_SIZE))
    {
        transformed.extend(
            block
                .iter()
                .zip(key_stream)
                .map(|(left, right)| left ^ right),
        );
    }
    let ciphertext = if encrypting { &transformed } else { payload };
    let hash = ghash(hash_subkey, aad, ciphertext).ok_or(AesGcmError::InputTooLong)?;
    let mut full_tag = [0; AES_BLOCK_SIZE];
    for ((output, mask), value) in full_tag
        .iter_mut()
        .zip(&encrypted_counters[..AES_BLOCK_SIZE])
        .zip(hash)
    {
        *output = mask ^ value;
    }
    let expected_tag = gcm_tag(full_tag, tag_bits);
    if let Some(supplied_tag) = supplied_tag {
        if !bool::from(expected_tag.as_slice().ct_eq(supplied_tag)) {
            transformed.fill(0);
            return Err(AesGcmError::AuthenticationFailed);
        }
        Ok(transformed)
    } else {
        transformed.extend_from_slice(&expected_tag);
        Ok(transformed)
    }
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
        let expected = hex("070a16b46b4d4144f79bdd9dd04a287c");
        assert_eq!(aes_cmac(&key, &message).unwrap().as_slice(), expected);
        assert_eq!(
            aes_cmac_with(&message, |blocks| encrypt_aes_ecb(&key, blocks))
                .unwrap()
                .as_slice(),
            expected
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
    fn aes_gcm_matches_nist_vectors_and_rejects_modified_tags() {
        let zero_key = [0; 16];
        let mut encrypted = aes_gcm_with(&[0; 12], &[], 128, &[0; 16], true, |blocks| {
            encrypt_aes_ecb(&zero_key, blocks)
        })
        .unwrap();
        assert_eq!(
            encrypted,
            hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );
        assert_eq!(
            aes_gcm_with(&[0; 12], &[], 128, &encrypted, false, |blocks| {
                encrypt_aes_ecb(&zero_key, blocks)
            })
            .unwrap(),
            [0; 16]
        );
        *encrypted.last_mut().unwrap() ^= 1;
        assert_eq!(
            aes_gcm_with(&[0; 12], &[], 128, &encrypted, false, |blocks| {
                encrypt_aes_ecb(&zero_key, blocks)
            }),
            Err(AesGcmError::AuthenticationFailed)
        );

        let key = hex("feffe9928665731c6d6a8f9467308308");
        let plaintext = hex(concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ));
        let iv = hex("cafebabefacedbad");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let encrypted = aes_gcm_with(&iv, &aad, 128, &plaintext, true, |blocks| {
            encrypt_aes_ecb(&key, blocks)
        })
        .unwrap();
        assert_eq!(
            encrypted,
            hex(concat!(
                "61353b4c2806934a777ff51fa22a4755",
                "699b2a714fcdc6f83766e5f97b6c7423",
                "73806900e49f24b22b097544d4896b42",
                "4989b5e1ebac0f07c23f4598",
                "3612d2e79e3b0785561be14aaca2fccb"
            ))
        );
        assert_eq!(
            aes_gcm_with(&iv, &aad, 128, &encrypted, false, |blocks| {
                encrypt_aes_ecb(&key, blocks)
            })
            .unwrap(),
            plaintext
        );
    }

    #[test]
    fn aes_ctr_matches_nist_sp_800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let plaintext = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = hex(concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee"
        ));
        let ciphertext = aes_ctr_with(128, counter, &plaintext, |blocks| {
            encrypt_aes_ecb(&key, blocks)
        })
        .unwrap();
        assert_eq!(ciphertext, expected);
        assert_eq!(
            aes_ctr_with(128, counter, &ciphertext, |blocks| {
                encrypt_aes_ecb(&key, blocks)
            })
            .unwrap(),
            plaintext
        );
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
    fn general_aes_ccm_matches_rfc_3610() {
        let key = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = hex("00000003020100a0a1a2a3a4a5");
        let aad = hex("0001020304050607");
        let plaintext = hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let expected = hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
        let crypt = |operation, blocks: &[u8]| match operation {
            AesCcmOperation::EncryptBlocks => encrypt_aes_ecb(&key, blocks),
            AesCcmOperation::CbcMac => {
                let encrypted = encrypt_aes_cbc(&key, &[0; AES_BLOCK_SIZE], blocks)?;
                Ok(encrypted[encrypted.len() - AES_BLOCK_SIZE..].to_vec())
            }
        };
        let ciphertext =
            aes_ccm_with(plaintext.len(), &nonce, &aad, 8, &plaintext, true, crypt).unwrap();
        assert_eq!(ciphertext, expected);
        assert_eq!(
            aes_ccm_with(plaintext.len(), &nonce, &aad, 8, &ciphertext, false, crypt,).unwrap(),
            plaintext
        );
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
