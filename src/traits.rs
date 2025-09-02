// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{order::Lsb0, slice::BitSlice, vec::BitVec};

/// Trait for hashing data with a fixed output size and byte input.
pub trait Hasher<const D_BYTES: usize> {
    /// Update the hasher with new byte data.
    ///
    /// # Errors
    /// An error will be returned if `update` is called after the hasher has been finalized.
    ///
    fn update(&mut self, data: &[u8]) -> Result<()>;
    /// Finalize the hash computation and return the result.
    ///
    /// # Errors
    ///
    fn finalize(&mut self, output: &mut [u8; D_BYTES]) -> Result<()>;
}

/// Trait for hashing data with a fixed output size and `BitSlice` input.
pub trait HasherBits<const D_BYTES: usize> {
    /// Update the hasher with new bits
    ///
    /// # Errors
    /// An error will be returned if `update_bits` is called after the hasher has been finalized.
    ///
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) -> Result<()>;
}

/// Trait for hashing data with an arbitrary output size and byte input data.
pub trait XofHasher {
    /// Update the hasher with new byte data.
    ///
    /// # Errors
    /// An error will be returned if `update` is called after the hasher has been finalized.
    ///
    fn update(&mut self, data: &[u8]) -> Result<()>;
    /// Finalize the absorbing phase.
    ///
    /// # Errors
    ///
    fn finalize(&mut self) -> Result<()>;
    /// Start the squeezing phase and fill the requested number of bytes.
    ///
    /// # Errors
    ///
    fn get_bytes(&mut self, output: &mut [u8], num_bytes: usize) -> Result<()>;
}

/// Trait for hashing data with an arbitrary output size and `BitSlice` input data.
pub trait XofHasherBits {
    /// Update the hasher with new bits
    ///
    /// # Errors
    /// An error will be returned if `update_bits` is called after the hasher has been finalized.
    ///
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) -> Result<()>;
    /// Start the squeezing phase and fill the requested number of bits.
    ///
    /// # Errors
    ///
    fn get_bits(&mut self, output: &mut BitVec<u8, Lsb0>, num_bits: usize) -> Result<()>;
}

/// A sponge trait for absorbing and squeezing data (Keccak for example)
pub(crate) trait Sponge {
    /// Update the sponge with the given data.
    ///
    /// # Errors
    /// An error will be returned if `update` is called after the hasher has been finalized.
    ///
    fn update(&mut self, data: &[u8]) -> Result<()>;

    /// Update the sponge with the given bits.
    ///
    /// # Errors
    /// An error will be returned if `update_bits` is called after the hasher has been finalized.
    ///
    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) -> Result<()>;

    /// Absorb the sponge data.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn absorb(&mut self) -> Result<()>;

    /// Squeeze data from the sponge until the output buffer is filled.   This works
    /// for byte-aligned output data.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn squeeze(&mut self, output: &mut [u8], num_bits: usize) -> Result<()>;

    /// Squeeze data from the sponge until the output buffer of bits is filled.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn squeeze_b(&mut self, output: &mut BitVec<u8, Lsb0>, num_bits: usize) -> Result<()>;
}
