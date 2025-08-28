// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{bits, order::Lsb0, slice::BitSlice};

use crate::{Sponge, sponge::Keccak1600Sponge};

pub(crate) mod shake128;
pub(crate) mod shake256;

/// SHA-3 XOF hash functions (SHAKE128 and SHAKE256)
#[derive(Clone, Debug)]
struct Shake {
    sponge: Keccak1600Sponge,
}

impl Shake {
    pub(crate) fn update(&mut self, data: &[u8]) {
        // Update the internal state with the new data
        self.sponge.update(data);
    }

    pub(crate) fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        // Update the internal state with the new bits
        self.sponge.update_bits(data);
    }

    pub(crate) fn finalize(&mut self, output: &mut [u8], num_bits: usize) -> Result<()> {
        // Append the SHAKE domain separation bits (0b1111) to the message
        self.sponge.update_bits(bits![u8, Lsb0; 1, 1, 1, 1]);
        // Start the absorbing phase
        self.sponge.absorb()?;
        // Start the squeezing phase
        self.sponge.squeeze(output, num_bits)?;
        Ok(())
    }
}
