// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{field::BitField, order::Lsb0, slice::BitSlice, vec::BitVec, view::BitView};

use crate::{Sha3Error, constants::ARR_SIZE, f_1600};

/// A sponge trait for absorbing and squeezing data (Keccak for example)
pub trait Sponge {
    /// Absorb input data into the sponge state.
    fn absorb(&mut self, data: &[u8]);

    /// Absorb input data as bits into the sponge state.
    fn absorb_bits(&mut self, data: &BitSlice<u8, Lsb0>);

    /// Squeezed output data from the sponge state.  The state will be squeezed multiple times if necessary to fill the output.
    ///
    /// # Errors
    /// This function will return an error if the number of bits to squeeze is invalid.
    fn squeezed(&mut self, output: &mut [u8], num_bits: usize) -> Result<()>;
}

#[derive(Clone, Debug)]
pub(crate) struct Keccak1600Sponge {
    // Internal state representation
    state: [u64; ARR_SIZE],
    // Message Data
    message: BitVec<u8, Lsb0>,
    rate: usize,
    capacity: usize,
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
            state: [0u64; ARR_SIZE],
            message: BitVec::new(),
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

    fn state_to_bits(&self) -> BitVec<u8, Lsb0> {
        let mut byte_vec = Vec::new();
        for s in &self.state {
            byte_vec.extend(s.to_le_bytes());
        }

        let mut bits_vec = BitVec::<u8, Lsb0>::new();

        for byte in byte_vec {
            let slice = byte.view_bits::<Lsb0>();
            bits_vec.extend_from_bitslice(slice);
        }
        bits_vec
    }

    fn squeeze(&mut self, output: &mut [u8], num_bits: &mut usize) {
        let state_bits = self.state_to_bits();

        if *num_bits <= state_bits.len() {
            let output_bits = &state_bits[..*num_bits];

            for (idx, eight_bits) in output_bits.chunks_exact(8).enumerate() {
                let value: u8 = eight_bits.load_le::<u8>();
                output[idx] = value;
            }
            *num_bits = 0;
        }
    }
}

impl Sponge for Keccak1600Sponge {
    fn absorb(&mut self, data: &[u8]) {
        // Update the internal state with the new data
        self.message.extend_from_raw_slice(data);
    }

    fn absorb_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        // Update the internal state with the new bits
        self.message.extend_from_bitslice(data);
    }

    fn squeezed(&mut self, output: &mut [u8], num_bits: usize) -> Result<()> {
        if output.len() == num_bits / 8 {
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

            // Squeeze output until we have enough bits
            let mut remaining_bits = num_bits;
            self.squeeze(output, &mut remaining_bits);

            while remaining_bits > 0 {
                self.keccak()?;
                self.squeeze(output, &mut remaining_bits);
            }
            Ok(())
        } else {
            Err(Sha3Error::OutputLengthMismatch(output.len(), num_bits / 8).into())
        }
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
