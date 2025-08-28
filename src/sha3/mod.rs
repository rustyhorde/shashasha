// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{bits, order::Lsb0, slice::BitSlice, vec::BitVec};

use crate::{Sponge, sponge::Keccak1600Sponge};

pub(crate) mod sha224;
pub(crate) mod sha256;
pub(crate) mod sha384;
pub(crate) mod sha512;

/// SHA-3 hash function
#[derive(Clone, Debug)]
struct Sha3<const B: usize> {
    sponge: Keccak1600Sponge,
}

impl<const B: usize> Sha3<B> {
    pub(crate) fn update(&mut self, data: &[u8]) {
        // Update the internal state with the new data
        self.sponge.update(data);
    }

    pub(crate) fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        // Update the internal state with the new bits
        self.sponge.update_bits(data);
    }

    pub(crate) fn finalize(&mut self, output: &mut [u8; B]) -> Result<()> {
        // Append the SHA-3 domain separation bits (0b01) to the message
        self.sponge.update_bits(bits![u8, Lsb0; 0, 1]);
        let num_bits = output.len() * 8;
        // Start the absorbing phase
        self.sponge.absorb()?;
        // Start the squeezing phase
        self.sponge.squeeze(output, num_bits)?;
        Ok(())
    }
}

#[allow(dead_code)]
fn b2h(bits: &BitVec<u8, Lsb0>, include_space: bool) -> Result<String> {
    use std::fmt::Write;

    let mut res = String::new();
    for i in 0..bits.len() / 8 {
        let mut value: u8 = 0;
        for j in 0..8 {
            value += u8::from(bits[8 * i + j]) * 2u8.pow(j.try_into()?);
        }
        write!(res, "{value:02X}")?;
        if include_space {
            res.push(' ');
        }
    }
    Ok(res)
}

#[allow(dead_code)]
pub(crate) fn display(bv: &BitVec<u8, Lsb0>) -> Result<()> {
    let chunks = bv.chunks_exact(128);
    let mut final_idx = 0;
    for (idx, bs) in &mut chunks.clone().enumerate() {
        eprintln!("{idx:04}: {}", b2h(&bs.to_bitvec(), true)?);
        final_idx = idx;
    }
    final_idx += 1;

    let rem = chunks.remainder();
    if !rem.is_empty() {
        eprintln!("{final_idx:04}: {}", b2h(&rem.to_bitvec(), true)?);
    }
    Ok(())
}
