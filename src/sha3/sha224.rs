// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{bits, order::Lsb0, slice::BitSlice, vec::BitVec};

use crate::{
    Hasher,
    constants::{ARR_SIZE, SHA3_224_BYTES, SHA3_224_CAPACITY, SHA3_224_RATE},
    sha3::Sha3,
};

/// SHA3-224 hash function
#[derive(Clone, Debug)]
pub struct Sha3_224 {
    inner: Sha3<{ SHA3_224_BYTES }>,
    message: BitVec<u8, Lsb0>,
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_224 {
    /// Create a new SHA3-224 hasher instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            message: BitVec::new(),
            inner: Sha3::<{ SHA3_224_BYTES }> {
                state: [0u64; ARR_SIZE],
            },
        }
    }

    pub(crate) fn state_to_bytes(&self) -> Vec<u8> {
        let mut output = self.inner.state_to_bytes(SHA3_224_BYTES);
        output.truncate(SHA3_224_BYTES);
        output
    }
}

impl Hasher<{ SHA3_224_BYTES }> for Sha3_224 {
    fn update(&mut self, data: &[u8]) {
        // Update the internal state with the new data
        self.message.extend_from_raw_slice(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        // Update the internal state with the new bits
        self.message.extend_from_bitslice(data);
    }

    fn finalize(&mut self, output: &mut [u8; SHA3_224_BYTES]) -> Result<()> {
        // Finalize the hash computation and return the result
        let rate = *SHA3_224_RATE;
        self.message.extend_from_bitslice(bits![u8, Lsb0; 0, 1]);

        let mut chunks = self.message.chunks_exact(rate);
        for bits in &mut chunks {
            let mut bv = bits.to_bitvec();
            self.inner.pad10star1(&mut bv, *SHA3_224_RATE)?;
            self.inner.zero_pad(&mut bv, *SHA3_224_CAPACITY);
            self.inner.xor_block(&bv)?;
            self.inner.keccak()?;
        }

        let rem = chunks.remainder();

        if !rem.is_empty() {
            let mut bv = rem.to_bitvec();
            self.inner.pad10star1(&mut bv, *SHA3_224_RATE)?;
            self.inner.zero_pad(&mut bv, *SHA3_224_CAPACITY);
            self.inner.xor_block(&bv)?;
            self.inner.keccak()?;
        }

        output
            .iter_mut()
            .zip(self.state_to_bytes().iter())
            .for_each(|(o, b)| *o = *b);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bitvec::{bits, order::Lsb0};

    use crate::{
        Hasher, Sha3_224,
        constants::SHA3_224_BYTES,
        sha3::test::{Mode, create_test_vector, format_output},
    };

    const SHA3_224_0_BITS: &str =
        "6B 4E 03 42 36 67 DB B7 3B 6E 15 45 4F 0E B1 AB D4 59 7F 9A 1B 07 8E 3F 5B 5A 6B C7";
    const SHA3_224_5_BITS: &str =
        "FF BA D5 DA 96 BA D7 17 89 33 02 06 DC 67 68 EC AE B1 B3 2D CA 6B 33 01 48 96 74 AB";
    const SHA3_224_30_BITS: &str =
        "D6 66 A5 14 CC 9D BA 25 AC 1B A6 9E D3 93 04 60 DE AA C9 85 1B 5F 0B AA B0 07 DF 3B";
    const SHA3_224_1600_BITS: &str =
        "93 76 81 6A BA 50 3F 72 F9 6C E7 EB 65 AC 09 5D EE E3 BE 4B F9 BB C2 A1 CB 7E 11 E0";
    const SHA3_224_1605_BITS: &str =
        "22 D2 F7 BB 0B 17 3F D8 C1 96 86 F9 17 31 66 E3 EE 62 73 80 47 D7 EA DD 69 EF B2 28";
    const SHA3_224_1630_BITS: &str =
        "4E 90 7B B1 05 78 61 F2 00 A5 99 E9 D4 F8 5B 02 D8 84 53 BF 5B 8A CE 9A C5 89 13 4C";

    #[test]
    /// <https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-224_msg0.pdf>
    fn test_sha3_224_0_bits() {
        let mut hasher = Sha3_224::new();
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_0_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf>
    fn test_sha3_224_5_bits() {
        let mut hasher = Sha3_224::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1]);
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_5_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg30.pdf>
    fn test_sha3_224_30_bits() {
        let mut hasher = Sha3_224::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0]);
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_30_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1600.pdf>
    fn test_sha3_224_1600_bits() {
        // Create 1600-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1600);
        assert_eq!(1600, bit_vec.len());
        let mut hasher = Sha3_224::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_1600_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1605.pdf>
    fn test_sha3_224_1605_bits() {
        // Create 1605-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1605);
        assert_eq!(1605, bit_vec.len());
        let mut hasher = Sha3_224::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_1605_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1630.pdf>
    fn test_sha3_224_1630_bits() {
        // Create 1630-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1630);
        assert_eq!(1630, bit_vec.len());
        let mut hasher = Sha3_224::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_224_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_224_1630_BITS, format_output(&result));
    }
}
