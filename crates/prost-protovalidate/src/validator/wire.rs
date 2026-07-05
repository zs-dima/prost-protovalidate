//! Low-level protobuf wire-format scanning shared by descriptor-set assembly
//! ([`super::descriptor_set`]) and edition normalization ([`super::editions`]).
//!
//! Both consumers scan untrusted descriptor bytes, so these helpers never
//! panic and never recurse: group skipping is iterative with a nesting
//! counter, bounding stack use regardless of input.

use prost::encoding::{WireType, decode_key, decode_varint};

/// Decode the length prefix of a length-delimited field.
pub(crate) fn decode_len(cursor: &mut &[u8]) -> Result<usize, &'static str> {
    let len = decode_varint(cursor).map_err(|_| "invalid length varint")?;
    usize::try_from(len).map_err(|_| "length does not fit in usize")
}

/// Skip a single wire value of the given type.
///
/// Groups are consumed iteratively up to their matching end-group tag.
/// A stray end-group tag (no matching start) is an error. Valid
/// `FileDescriptorSet` bytes never contain groups; this path exists so
/// malformed or unknown input is skipped safely instead of aborting the scan.
pub(crate) fn skip_wire_value(cursor: &mut &[u8], wire_type: WireType) -> Result<(), &'static str> {
    match wire_type {
        WireType::StartGroup => {
            let mut depth: usize = 1;
            while depth > 0 {
                let (_, inner) = decode_key(cursor).map_err(|_| "invalid key inside group")?;
                match inner {
                    WireType::StartGroup => depth += 1,
                    WireType::EndGroup => depth -= 1,
                    scalar => skip_scalar(cursor, scalar)?,
                }
            }
            Ok(())
        }
        WireType::EndGroup => Err("unexpected end-group tag"),
        scalar => skip_scalar(cursor, scalar),
    }
}

/// Skip a non-group wire value.
fn skip_scalar(cursor: &mut &[u8], wire_type: WireType) -> Result<(), &'static str> {
    match wire_type {
        WireType::Varint => {
            decode_varint(cursor).map_err(|_| "invalid varint")?;
            Ok(())
        }
        WireType::LengthDelimited => {
            let len = decode_len(cursor)?;
            if cursor.len() < len {
                return Err("truncated length-delimited field");
            }
            *cursor = &cursor[len..];
            Ok(())
        }
        WireType::ThirtyTwoBit => {
            if cursor.len() < 4 {
                return Err("truncated 32-bit field");
            }
            *cursor = &cursor[4..];
            Ok(())
        }
        WireType::SixtyFourBit => {
            if cursor.len() < 8 {
                return Err("truncated 64-bit field");
            }
            *cursor = &cursor[8..];
            Ok(())
        }
        WireType::StartGroup | WireType::EndGroup => Err("unexpected group tag"),
    }
}

#[cfg(test)]
mod tests {
    use prost::encoding::{WireType, decode_key, encode_key, encode_varint};

    use super::{decode_len, skip_wire_value};

    #[test]
    fn decodes_length_prefix() {
        let mut buf = Vec::new();
        encode_varint(5, &mut buf);
        buf.extend_from_slice(b"hello");
        let mut cursor = buf.as_slice();
        assert_eq!(decode_len(&mut cursor), Ok(5));
        assert_eq!(cursor, b"hello");
    }

    #[test]
    fn skips_scalar_values() {
        let mut buf = Vec::new();
        encode_varint(300, &mut buf);
        let mut cursor = buf.as_slice();
        assert_eq!(skip_wire_value(&mut cursor, WireType::Varint), Ok(()));
        assert!(cursor.is_empty());

        let mut buf = Vec::new();
        encode_varint(3, &mut buf);
        buf.extend_from_slice(b"abc");
        let mut cursor = buf.as_slice();
        assert_eq!(
            skip_wire_value(&mut cursor, WireType::LengthDelimited),
            Ok(())
        );
        assert!(cursor.is_empty());

        let buf = [0u8; 4];
        let mut cursor = buf.as_slice();
        assert_eq!(skip_wire_value(&mut cursor, WireType::ThirtyTwoBit), Ok(()));
        assert!(cursor.is_empty());

        let buf = [0u8; 8];
        let mut cursor = buf.as_slice();
        assert_eq!(skip_wire_value(&mut cursor, WireType::SixtyFourBit), Ok(()));
        assert!(cursor.is_empty());
    }

    #[test]
    fn rejects_truncated_values() {
        let mut buf = Vec::new();
        encode_varint(10, &mut buf);
        buf.extend_from_slice(b"abc");
        let mut cursor = buf.as_slice();
        assert!(skip_wire_value(&mut cursor, WireType::LengthDelimited).is_err());

        let buf = [0u8; 3];
        let mut cursor = buf.as_slice();
        assert!(skip_wire_value(&mut cursor, WireType::ThirtyTwoBit).is_err());
    }

    #[test]
    fn rejects_stray_end_group() {
        let mut cursor: &[u8] = &[];
        assert!(skip_wire_value(&mut cursor, WireType::EndGroup).is_err());
    }

    #[test]
    fn skips_nested_groups_with_payload() {
        // group { varint field; group { bytes field } }
        let mut buf = Vec::new();
        encode_key(2, WireType::Varint, &mut buf);
        encode_varint(42, &mut buf);
        encode_key(3, WireType::StartGroup, &mut buf);
        encode_key(4, WireType::LengthDelimited, &mut buf);
        encode_varint(2, &mut buf);
        buf.extend_from_slice(b"ok");
        encode_key(3, WireType::EndGroup, &mut buf);
        encode_key(1, WireType::EndGroup, &mut buf);

        let mut cursor = buf.as_slice();
        assert_eq!(skip_wire_value(&mut cursor, WireType::StartGroup), Ok(()));
        assert!(cursor.is_empty());
    }

    #[test]
    fn deeply_nested_groups_do_not_exhaust_the_stack() {
        // 100k nesting levels would overflow a recursive skipper.
        const DEPTH: usize = 100_000;
        let mut buf = Vec::new();
        for _ in 0..DEPTH {
            encode_key(1, WireType::StartGroup, &mut buf);
        }
        for _ in 0..DEPTH {
            encode_key(1, WireType::EndGroup, &mut buf);
        }

        let mut cursor = buf.as_slice();
        let (_, wire_type) = decode_key(&mut cursor).expect("valid key");
        assert_eq!(wire_type, WireType::StartGroup);
        assert_eq!(skip_wire_value(&mut cursor, WireType::StartGroup), Ok(()));
        assert!(cursor.is_empty());
    }

    #[test]
    fn unterminated_group_is_an_error() {
        let mut buf = Vec::new();
        encode_key(1, WireType::StartGroup, &mut buf);
        let mut cursor = buf.as_slice();
        let (_, wire_type) = decode_key(&mut cursor).expect("valid key");
        assert!(skip_wire_value(&mut cursor, wire_type).is_err());
    }
}
