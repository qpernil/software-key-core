//! RFC 9881 / RFC 9935 private-key CHOICE adapters.
use ml_dsa::pkcs8::{
    self, AlgorithmIdentifierRef, PrivateKeyInfoRef, SecretDocument,
    der::{
        self, Decode, Encode, Reader, Tag, TagMode, TagNumber,
        asn1::{AnyRef, BitStringRef, ContextSpecific, OctetStringRef},
    },
};
use zeroize::Zeroizing;

pub(crate) enum PrivateEncoding<'a> {
    Seed(&'a [u8]),
    Expanded(&'a [u8]),
    Both { seed: &'a [u8], expanded: &'a [u8] },
}

pub(crate) struct PrivateKey<'a> {
    pub encoding: PrivateEncoding<'a>,
    pub public: Option<&'a [u8]>,
}

pub(crate) fn decode<'a>(
    encoded: &'a [u8],
    algorithm: AlgorithmIdentifierRef<'static>,
) -> pkcs8::Result<PrivateKey<'a>> {
    let info = PrivateKeyInfoRef::from_der(encoded)?;
    info.algorithm.assert_algorithm_oid(algorithm.oid)?;
    if info.algorithm.parameters.is_some() {
        return Err(pkcs8::KeyError::Invalid.into());
    }
    let bytes = info.private_key.as_bytes();
    let mut reader = der::SliceReader::new(bytes)?;
    let encoding = match Tag::peek(&reader)? {
        Tag::ContextSpecific {
            number: TagNumber(0),
            constructed: false,
        } => {
            let seed =
                ContextSpecific::<&OctetStringRef>::decode_implicit(&mut reader, TagNumber(0))?
                    .ok_or(pkcs8::KeyError::Invalid)?;
            PrivateEncoding::Seed(seed.value.as_bytes())
        }
        Tag::OctetString => {
            PrivateEncoding::Expanded(<&OctetStringRef>::decode(&mut reader)?.as_bytes())
        }
        Tag::Sequence => {
            let both = AnyRef::decode(&mut reader)?;
            both.sequence(|inner| -> der::Result<_> {
                let seed = <&OctetStringRef>::decode(inner)?.as_bytes();
                let expanded = <&OctetStringRef>::decode(inner)?.as_bytes();
                Ok(PrivateEncoding::Both { seed, expanded })
            })?
        }
        _ => return Err(pkcs8::KeyError::Invalid.into()),
    };
    reader.finish()?;
    let public = info
        .public_key
        .map(|key| key.as_bytes().ok_or(pkcs8::KeyError::Invalid))
        .transpose()?;
    Ok(PrivateKey { encoding, public })
}

pub(crate) fn encode(
    algorithm: AlgorithmIdentifierRef<'static>,
    encoding: PrivateEncoding<'_>,
    public: Option<&[u8]>,
) -> pkcs8::Result<Zeroizing<Vec<u8>>> {
    let inner = match encoding {
        PrivateEncoding::Seed(seed) => ContextSpecific {
            tag_mode: TagMode::Implicit,
            tag_number: TagNumber(0),
            value: OctetStringRef::new(seed)?,
        }
        .to_der()?,
        PrivateEncoding::Expanded(expanded) => OctetStringRef::new(expanded)?.to_der()?,
        PrivateEncoding::Both { seed, expanded } => {
            let mut content = Zeroizing::new(OctetStringRef::new(seed)?.to_der()?);
            let encoded_expanded = Zeroizing::new(OctetStringRef::new(expanded)?.to_der()?);
            content.extend_from_slice(&encoded_expanded);
            AnyRef::new(Tag::Sequence, &content)?.to_der()?
        }
    };
    let inner = Zeroizing::new(inner);
    let mut info = PrivateKeyInfoRef::new(algorithm, OctetStringRef::new(&inner)?);
    info.public_key = public.map(BitStringRef::from_bytes).transpose()?;
    let document = SecretDocument::encode_msg(&info)?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}
