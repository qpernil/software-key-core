//! SP 800-108 counter KDF with AES-CMAC and caller-ordered public input fields.
use crate::software_symmetric::aes_cmac;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterKdfError {
    InvalidKeyLength,
    InvalidParameters,
    OutputTooLong,
}

/// Parameter errors and failures from the caller's CMAC implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterKdfOperationError<E> {
    Kdf(CounterKdfError),
    Cmac(E),
}

impl<E> From<CounterKdfError> for CounterKdfOperationError<E> {
    fn from(error: CounterKdfError) -> Self {
        Self::Kdf(error)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IntegerFormat {
    pub width_bits: u8,
    pub little_endian: bool,
}

impl IntegerFormat {
    fn valid(self, max_bits: u8) -> bool {
        self.width_bits != 0 && self.width_bits <= max_bits && self.width_bits.is_multiple_of(8)
    }

    fn fits(self, value: u64) -> bool {
        self.width_bits == 64 || value < (1u64 << self.width_bits)
    }

    fn append(self, value: u64, input: &mut Vec<u8>) {
        let width = usize::from(self.width_bits / 8);
        if self.little_endian {
            input.extend_from_slice(&value.to_le_bytes()[..width]);
        } else {
            input.extend_from_slice(&value.to_be_bytes()[8 - width..]);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum LengthMethod {
    /// Number of requested key bits.
    Key,
    /// Number of generated CMAC bits, including the unused final block suffix.
    Segments,
}

#[derive(Clone, Copy)]
pub enum CounterKdfField<'a> {
    Bytes(&'a [u8]),
    Counter(IntegerFormat),
    Length(IntegerFormat, LengthMethod),
}

/// Derive one byte-aligned key. Counter starts at one; output is truncated on
/// the right. Counter widths are 8/16/24/32 bits, length widths 8..=64 in steps
/// of eight. Exactly one counter and at most one length field are accepted.
/// No protocol layout, object policy, or persistent state is imposed here.
pub fn cmac_counter_kdf(
    key: &[u8],
    fields: &[CounterKdfField<'_>],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CounterKdfError> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(CounterKdfError::InvalidKeyLength);
    }
    cmac_counter_kdf_with(fields, output_length, |input| aes_cmac(key, input)).map_err(|error| {
        match error {
            CounterKdfOperationError::Kdf(error) => error,
            CounterKdfOperationError::Cmac(_) => CounterKdfError::InvalidKeyLength,
        }
    })
}

/// The same KDF using a caller-supplied AES-CMAC operation. The base key can
/// remain behind a hardware handle. All field validation precedes the first
/// CMAC call; failures discard partially derived output in zeroizing storage.
pub fn cmac_counter_kdf_with<E>(
    fields: &[CounterKdfField<'_>],
    output_length: usize,
    mut cmac: impl FnMut(&[u8]) -> Result<[u8; 16], E>,
) -> Result<Zeroizing<Vec<u8>>, CounterKdfOperationError<E>> {
    use CounterKdfError::*;
    if output_length == 0 {
        return Err(InvalidParameters.into());
    }
    let blocks = output_length.div_ceil(16);
    let key_bits = output_length.checked_mul(8).ok_or(OutputTooLong)? as u64;
    let segment_bits = blocks.checked_mul(128).ok_or(OutputTooLong)? as u64;
    let mut counter = None;
    let mut length = None;
    let mut input_length = 0usize;
    for field in fields {
        let size = match *field {
            CounterKdfField::Bytes(bytes) => bytes.len(),
            CounterKdfField::Counter(format) => {
                if !format.valid(32) || counter.replace(format).is_some() {
                    return Err(InvalidParameters.into());
                }
                if !format.fits(blocks as u64) {
                    return Err(OutputTooLong.into());
                }
                usize::from(format.width_bits / 8)
            }
            CounterKdfField::Length(format, method) => {
                if !format.valid(64) || length.is_some() {
                    return Err(InvalidParameters.into());
                }
                let bits = match method {
                    LengthMethod::Key => key_bits,
                    LengthMethod::Segments => segment_bits,
                };
                if !format.fits(bits) {
                    return Err(OutputTooLong.into());
                }
                length = Some(bits);
                usize::from(format.width_bits / 8)
            }
        };
        input_length = input_length.checked_add(size).ok_or(InvalidParameters)?;
    }
    if counter.is_none() || input_length > isize::MAX as usize {
        return Err(InvalidParameters.into());
    }
    let mut result = Zeroizing::new(Vec::with_capacity(output_length));
    let mut input = Zeroizing::new(Vec::with_capacity(input_length));
    for iteration in 1..=blocks {
        input.clear();
        for field in fields {
            match *field {
                CounterKdfField::Bytes(bytes) => input.extend_from_slice(bytes),
                CounterKdfField::Counter(format) => format.append(iteration as u64, &mut input),
                CounterKdfField::Length(format, _) => {
                    format.append(length.ok_or(InvalidParameters)?, &mut input)
                }
            }
        }
        let block = Zeroizing::new(cmac(&input).map_err(CounterKdfOperationError::Cmac)?);
        let remaining = (output_length - result.len()).min(16);
        result.extend_from_slice(&block[..remaining]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn scp03_requested_lengths_match_independent_openssl_cmac_vectors() {
        let key: Vec<u8> = (0x40..0x50).collect();
        let label = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0];
        let context = hex("01020304050607081112131415161718");
        let fields = [
            CounterKdfField::Bytes(&label),
            CounterKdfField::Length(
                IntegerFormat {
                    width_bits: 16,
                    little_endian: false,
                },
                LengthMethod::Key,
            ),
            CounterKdfField::Counter(IntegerFormat {
                width_bits: 8,
                little_endian: false,
            }),
            CounterKdfField::Bytes(&context),
        ];
        for (length, expected) in [
            (16, "d99675d4a95c58de629225730cddb758"),
            (24, "cde1b0fba174796ab9f28d81848d5c7481724bfc0cf193b9"),
            (
                32,
                "451ca221762da5dc0c4db08a2af7147bc25881b77d52b1d3e702f693f440164f",
            ),
        ] {
            assert_eq!(
                cmac_counter_kdf(&key, &fields, length).unwrap().as_slice(),
                hex(expected)
            );
        }
    }

    #[test]
    fn field_order_endianness_and_length_methods_match_openssl_vectors() {
        let key: Vec<u8> = (0x40..0x50).collect();
        for (little_endian, method, expected) in [
            (
                false,
                LengthMethod::Key,
                "be434dc89f7c8d64d9e66c260fb5de321cbcfd74a7a93ded",
            ),
            (
                false,
                LengthMethod::Segments,
                "886fa95692f2b451f3e4c92a4f90b43ed571206b42e9a6e2",
            ),
            (
                true,
                LengthMethod::Key,
                "bc39563583409986de95ceb37ec76e35126e3d8ec83476ac",
            ),
            (
                true,
                LengthMethod::Segments,
                "321545d9630f704533760c60f3deee6f7ded9d257992e0f4",
            ),
        ] {
            let fields = [
                CounterKdfField::Counter(IntegerFormat {
                    width_bits: 32,
                    little_endian,
                }),
                CounterKdfField::Bytes(b"label\0context"),
                CounterKdfField::Length(
                    IntegerFormat {
                        width_bits: 16,
                        little_endian,
                    },
                    method,
                ),
            ];
            assert_eq!(
                cmac_counter_kdf(&key, &fields, 24).unwrap().as_slice(),
                hex(expected)
            );
        }
    }

    #[test]
    fn rejects_missing_duplicate_invalid_and_overflowing_fields() {
        let counter = CounterKdfField::Counter(IntegerFormat {
            width_bits: 8,
            little_endian: false,
        });
        assert_eq!(
            cmac_counter_kdf(&[0; 16], &[counter], 16)
                .unwrap()
                .as_slice(),
            hex("1f8262956c5c259946a3d370fe969234")
        );
        let length = CounterKdfField::Length(
            IntegerFormat {
                width_bits: 8,
                little_endian: false,
            },
            LengthMethod::Key,
        );
        for fields in [
            vec![],
            vec![length],
            vec![counter, counter],
            vec![counter, length, length],
            vec![CounterKdfField::Counter(IntegerFormat {
                width_bits: 7,
                little_endian: false,
            })],
        ] {
            assert_eq!(
                cmac_counter_kdf(&[0; 16], &fields, 16).unwrap_err(),
                CounterKdfError::InvalidParameters
            );
        }
        assert_eq!(
            cmac_counter_kdf(&[0; 16], &[counter], 4096).unwrap_err(),
            CounterKdfError::OutputTooLong
        );
        assert_eq!(
            cmac_counter_kdf(&[0; 16], &[counter, length], 32).unwrap_err(),
            CounterKdfError::OutputTooLong
        );
        assert_eq!(
            cmac_counter_kdf(&[0; 15], &[counter], 16).unwrap_err(),
            CounterKdfError::InvalidKeyLength
        );
        assert_eq!(
            cmac_counter_kdf(&[0; 16], &[counter], 0).unwrap_err(),
            CounterKdfError::InvalidParameters
        );
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;

    #[test]
    fn validates_before_cmac_and_propagates_failure_without_more_calls() {
        let counter = CounterKdfField::Counter(IntegerFormat {
            width_bits: 8,
            little_endian: false,
        });
        for (fields, length) in [(vec![], 16), (vec![counter], 4096), (vec![counter], 0)] {
            assert!(matches!(
                cmac_counter_kdf_with(&fields, length, |_| -> Result<[u8; 16], ()> {
                    panic!("invalid parameters reached CMAC")
                }),
                Err(CounterKdfOperationError::Kdf(_))
            ));
        }
        let mut calls = 0;
        let result = cmac_counter_kdf_with(&[counter], 48, |input| {
            calls += 1;
            assert_eq!(input, &[calls]);
            if calls == 2 {
                Err("device failure")
            } else {
                Ok([0xaa; 16])
            }
        });
        assert_eq!(calls, 2);
        assert_eq!(
            result.unwrap_err(),
            CounterKdfOperationError::Cmac("device failure")
        );
    }
}
