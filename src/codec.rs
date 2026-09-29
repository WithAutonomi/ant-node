//! Exactly-sized postcard encoding shared by the node's wire formats.

use serde::Serialize;

/// Why [`encode_exact`] produced no bytes.
#[derive(Debug)]
pub enum ExactEncodeError {
    /// Postcard could not serialize the value.
    Serialize(postcard::Error),
    /// The encoding would be `size` bytes, over `limit`; nothing was allocated.
    TooLarge { size: usize, limit: usize },
}

/// Encode `value` into a buffer of exactly its serialized size, refusing
/// before anything is allocated if that size is over `limit`.
///
/// A growing `Vec` would otherwise keep up to twice the needed capacity for
/// as long as the bytes are held, and chunk-carrying messages are held while
/// they are sent. Sizing first costs next to nothing: postcard's sizing pass
/// adds a byte string's length in one step, and compiles a plain `u8`
/// sequence's per-byte count down to a length too.
pub fn encode_exact<T: Serialize + ?Sized>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, ExactEncodeError> {
    let size =
        postcard::experimental::serialized_size(value).map_err(ExactEncodeError::Serialize)?;
    if size > limit {
        return Err(ExactEncodeError::TooLarge { size, limit });
    }
    postcard::to_extend(value, Vec::with_capacity(size)).map_err(ExactEncodeError::Serialize)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encodes_into_exactly_the_serialized_size() {
        let value = vec![0xABu8; 70_000];
        let bytes = encode_exact(&value, usize::MAX).expect("encode");
        assert_eq!(bytes, postcard::to_stdvec(&value).expect("reference"));
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn refuses_an_encoding_over_the_limit() {
        let value = vec![1u8; 100];
        let size = postcard::to_stdvec(&value).expect("reference").len();
        assert!(encode_exact(&value, size).is_ok());
        assert!(matches!(
            encode_exact(&value, size - 1),
            Err(ExactEncodeError::TooLarge { size: s, limit }) if s == size && limit == size - 1
        ));
    }
}
