// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{field::BitField, order::Lsb0, slice::BitSlice, vec::BitVec, view::BitView};

use crate::{Sha3Error, constants::LANE_COUNT, f_1600, traits::Sponge};

#[derive(Clone, Debug)]
pub(crate) struct Keccak1600Sponge {
    // Internal state representation
    state: [u64; LANE_COUNT],
    // Message Data
    message: BitVec<u8, Lsb0>,
    rate: usize,
    capacity: usize,
    output: BitVec<u8, Lsb0>,
}

impl Default for Keccak1600Sponge {
    fn default() -> Self {
        Self::new(usize::default(), usize::default())
    }
}

impl Keccak1600Sponge {
    /// Create a new Keccak-f[1600] sponge.
    #[must_use]
    pub(crate) fn new(rate: usize, capacity: usize) -> Self {
        Self {
            state: [0u64; LANE_COUNT],
            message: BitVec::new(),
            output: BitVec::new(),
            rate,
            capacity,
        }
    }

    fn xor_block(&mut self, bits: &BitVec<u8, Lsb0>) -> Result<()> {
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

    fn keccak(&mut self) -> Result<()> {
        f_1600(&mut self.state)?;
        Ok(())
    }

    fn fill_output(&mut self) {
        self.output.clear();
        let mut byte_vec = Vec::new();
        for s in &self.state {
            byte_vec.extend(s.to_le_bytes());
        }

        let mut bits_vec = BitVec::<u8, Lsb0>::new();

        for byte in byte_vec {
            let slice = byte.view_bits::<Lsb0>();
            bits_vec.extend_from_bitslice(slice);
        }
        self.output.extend_from_bitslice(&bits_vec[..self.rate]);
    }

    fn squeeze(&mut self, output: &mut [u8], num_bits: usize) -> Result<()> {
        let mut bit_vec = BitVec::<u8, Lsb0>::new();
        self.squeeze_b(&mut bit_vec, num_bits)?;

        for (idx, eight_bits) in bit_vec.chunks_exact(8).enumerate() {
            let value: u8 = eight_bits.load_le::<u8>();
            output[idx] = value;
        }
        Ok(())
    }

    fn squeeze_b(&mut self, output: &mut BitVec<u8, Lsb0>, requested_bits: usize) -> Result<()> {
        if self.output.is_empty() {
            self.fill_output();
            self.output.reverse();
        }
        let mut num_bits = requested_bits;

        while num_bits > 0 {
            while let Some(bit) = self.output.pop() {
                output.push(bit);
                num_bits -= 1;
                if num_bits == 0 {
                    break;
                }
            }
            if num_bits > 0 {
                self.keccak()?;
                self.fill_output();
                self.output.reverse();
            }
        }
        Ok(())
    }
}

impl Sponge for Keccak1600Sponge {
    fn update(&mut self, data: &[u8]) {
        // Update the internal state with the new data
        self.message.extend_from_raw_slice(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        // Update the internal state with the new bits
        self.message.extend_from_bitslice(data);
    }

    fn absorb(&mut self) -> Result<()> {
        // Process the absorbed message
        let mut chunks = self.message.chunks_exact(self.rate);
        let mut bvs = Vec::new();
        for bits in &mut chunks {
            let mut bv = bits.to_bitvec();
            pad10star1(&mut bv, self.rate)?;
            zero_pad(&mut bv, self.capacity);
            bvs.push(bv);
        }

        let rem = chunks.remainder();

        if !rem.is_empty() {
            let mut bv = rem.to_bitvec();
            pad10star1(&mut bv, self.rate)?;
            zero_pad(&mut bv, self.capacity);
            bvs.push(bv);
        }

        for bv in bvs {
            self.xor_block(&bv)?;
            self.keccak()?;
        }

        Ok(())
    }

    fn squeeze(&mut self, output: &mut [u8], num_bits: usize) -> Result<()> {
        if output.len() == num_bits / 8 {
            self.squeeze(output, num_bits)
        } else {
            Err(Sha3Error::OutputLengthMismatch(output.len(), num_bits / 8).into())
        }
    }

    fn squeeze_b(&mut self, output: &mut BitVec<u8, Lsb0>, num_bits: usize) -> Result<()> {
        self.squeeze_b(output, num_bits)
    }
}

fn pad10star1(bits: &mut BitVec<u8, Lsb0>, rate_bits: usize) -> Result<()> {
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

fn zero_pad(bits: &mut BitVec<u8, Lsb0>, capacity_bits: usize) {
    let zero_buffer = vec![0u8; capacity_bits / 8];
    bits.extend_from_raw_slice(&zero_buffer);
}
