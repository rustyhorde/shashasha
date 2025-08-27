// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{order::Lsb0, slice::BitSlice, vec::BitVec};

use crate::{constants::ARR_SIZE, f_1600};

pub(crate) mod sha224;

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

/// SHA-3 hash function
#[derive(Clone, Debug)]
struct Sha3<const B: usize> {
    state: [u64; ARR_SIZE],
}

impl<const B: usize> Sha3<B> {
    #[allow(clippy::unused_self)]
    pub(crate) fn pad10star1(&self, bits: &mut BitVec<u8, Lsb0>, rate_bits: usize) -> Result<()> {
        let len = bits.len();
        if len < rate_bits {
            let len = isize::try_from(len)?;
            let j = (-len - 2).rem_euclid(isize::try_from(rate_bits)?);

            bits.push(true);

            for _ in 0..j {
                bits.push(false);
            }

            bits.push(true);
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn zero_pad(&self, bits: &mut BitVec<u8, Lsb0>, capacity_bits: usize) {
        let zero_buffer = vec![0u8; capacity_bits / 8];
        bits.extend_from_raw_slice(&zero_buffer);
    }

    pub(crate) fn xor_block(&mut self, bits: &BitVec<u8, Lsb0>) -> Result<()> {
        let mut chunks = bits.chunks_exact(64);

        for (s, chunk) in self.state.iter_mut().zip(&mut chunks) {
            let mut value: u64 = 0;
            for (j, bit) in chunk.iter().enumerate() {
                value += u64::from(*bit) * 2u64.pow(j.try_into()?);
            }
            *s ^= value;
        }
        Ok(())
    }

    pub(crate) fn state_to_bytes(&self, truncate: usize) -> Vec<u8> {
        let mut output = Vec::new();
        for s in &self.state {
            output.extend(s.to_le_bytes());
        }

        output.truncate(truncate);
        output
    }

    pub(crate) fn keccak(&mut self) -> Result<()> {
        f_1600(&mut self.state)?;
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
fn display(bv: &BitVec<u8, Lsb0>) -> Result<()> {
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

#[cfg(test)]
mod test {
    use std::fmt::Write;

    use bitvec::{bits, bitvec, order::Lsb0, vec::BitVec};

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Mode {
        Sha3_1600,
        Sha3_1605,
        Sha3_1630,
    }

    pub(crate) fn create_test_vector(mode: Mode) -> BitVec<u8, Lsb0> {
        // Create 1600-bit test vector
        let mut bit_vec = bitvec![u8, Lsb0;];
        for _ in 0..50 {
            bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]);
        }

        match mode {
            Mode::Sha3_1600 => {}
            // Add 5 bits for 1605-bit test vector
            Mode::Sha3_1605 => {
                bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0]);
            }
            // Add 30 bits for 1630-bit test vector
            Mode::Sha3_1630 => {
                bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1]);
            }
        }
        bit_vec
    }

    pub(crate) fn format_output(result: &[u8]) -> String {
        result
            .iter()
            .fold(String::new(), |mut acc, x| {
                write!(acc, "{x:02X} ").unwrap();
                acc
            })
            .trim_end()
            .to_string()
    }
}
