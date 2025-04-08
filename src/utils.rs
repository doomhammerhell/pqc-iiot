//! Utility functions for cryptographic operations

use crate::Result;
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};

/// Constant-time comparison of two byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Fills a buffer with random bytes using a cryptographically secure RNG
pub fn fill_random<R, const N: usize>(rng: &mut R, buffer: &mut Vec<u8, N>) -> Result<()>
where
    R: CryptoRng + RngCore,
{
    let mut temp = [0u8; 32];
    rng.fill_bytes(&mut temp);
    buffer
        .extend_from_slice(&temp)
        .map_err(|_| crate::Error::BufferTooSmall)
}

/// Converts a byte slice to a fixed-size array
pub fn to_array<const N: usize>(slice: &[u8]) -> Option<[u8; N]> {
    if slice.len() != N {
        return None;
    }
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Some(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &b[..3]));
    }

    #[test]
    fn test_fill_random() {
        let mut rng = thread_rng();
        let mut buffer: Vec<u8, 32> = Vec::new();

        assert!(fill_random(&mut rng, &mut buffer).is_ok());
        assert_eq!(buffer.len(), 32);

        let mut buffer2: Vec<u8, 32> = Vec::new();
        assert!(fill_random(&mut rng, &mut buffer2).is_ok());
        assert_ne!(buffer, buffer2);
    }

    #[test]
    fn test_to_array() {
        let slice = [1, 2, 3, 4];
        let array = to_array::<4>(&slice);
        assert!(array.is_some());
        assert_eq!(array.unwrap(), [1, 2, 3, 4]);

        let array = to_array::<5>(&slice);
        assert!(array.is_none());
    }
}
