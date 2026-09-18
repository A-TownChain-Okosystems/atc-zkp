// Copyright (c) 2026 Michael Wroblewski — Apache-2.0
//! Canonical hashing primitives for the ZKP boundary.
//!
//! This crate intentionally exposes hashing only; it does not implement
//! elliptic-curve arithmetic or a proof system.

use sha2::{Digest, Sha256};

pub const MAX_HASH_INPUT_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    InputTooLarge,
}

pub fn sha256(input: &[u8]) -> Result<[u8; 32], HashError> {
    if input.len() > MAX_HASH_INPUT_BYTES {
        return Err(HashError::InputTooLarge);
    }
    let digest = Sha256::digest(input);
    Ok(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256(b"abc").unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn hash_rejects_oversized_input() {
        assert_eq!(
            sha256(&vec![0u8; MAX_HASH_INPUT_BYTES + 1]),
            Err(HashError::InputTooLarge)
        );
    }
}
