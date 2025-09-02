// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{bits, order::Lsb0, slice::BitSlice};

use crate::{Sha3Error, sponge::Keccak1600Sponge, traits::Sponge};

pub(crate) mod sha224;
pub(crate) mod sha256;
pub(crate) mod sha384;
pub(crate) mod sha512;

/// SHA-3 hash function
#[derive(Clone, Debug)]
struct Sha3<const B: usize> {
    sponge: Keccak1600Sponge,
    finalized: bool,
}

impl<const B: usize> Sha3<B> {
    pub(crate) fn update(&mut self, data: &[u8]) -> Result<()> {
        // Update the internal state with the new data
        if self.finalized {
            Err(Sha3Error::Finalized.into())
        } else {
            self.sponge.update(data)
        }
    }

    pub(crate) fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) -> Result<()> {
        // Update the internal state with the new bits
        if self.finalized {
            Err(Sha3Error::Finalized.into())
        } else {
            self.sponge.update_bits(data)
        }
    }

    pub(crate) fn finalize(&mut self, output: &mut [u8; B]) -> Result<()> {
        if self.finalized {
            Err(Sha3Error::Finalized.into())
        } else {
            // Append the SHA-3 domain separation bits (0b01) to the message
            self.sponge.update_bits(bits![u8, Lsb0; 0, 1])?;
            let num_bits = output.len() * 8;
            // Start the absorbing phase
            self.sponge.absorb()?;
            // Start the squeezing phase
            self.sponge.squeeze(output, num_bits)?;
            self.finalized = true;
            Ok(())
        }
    }
}
