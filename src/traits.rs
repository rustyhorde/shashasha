// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{order::Lsb0, slice::BitSlice};

/// Trait for hashing data.
pub trait Hasher<const D_BYTES: usize> {
    /// Update the hasher with new byte data.
    fn update(&mut self, data: &[u8]);
    /// Update the hasher with new bits
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>);
    /// Finalize the hash computation and return the result.
    ///
    /// # Errors
    ///
    fn finalize(&mut self, output: &mut [u8; D_BYTES]) -> Result<()>;
}

/// Trait for hashing data.
pub trait XofHasher {
    /// Update the hasher with new byte data.
    fn update(&mut self, data: &[u8]);
    /// Update the hasher with new bits
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>);
    /// Finalize the hash computation and return the result.
    ///
    /// # Errors
    ///
    fn finalize(&mut self, output: &mut [u8]) -> Result<()>;
}

/// A sponge trait for absorbing and squeezing data (Keccak for example)
pub trait Sponge {
    /// Update the sponge with the given data.
    fn update(&mut self, data: &[u8]);

    /// Update the sponge with the given bits.
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>);

    /// Absorb the sponge data.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn absorb(&mut self) -> Result<()>;

    /// Squeeze data from the sponge until the output buffer is filled.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn squeeze(&mut self, output: &mut [u8], num_bits: usize) -> Result<()>;
}
