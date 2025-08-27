// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{order::Lsb0, slice::BitSlice, vec::BitVec};

use crate::{
    Hasher,
    constants::{ARR_SIZE, SHA3_512_BYTES, SHA3_512_CAPACITY, SHA3_512_RATE},
    sha3::Sha3,
};

/// SHA3-512 hash function
#[derive(Clone, Debug)]
pub struct Sha3_512 {
    inner: Sha3<{ SHA3_512_BYTES }>,
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512 {
    /// Create a new SHA3-512 hasher instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3::<{ SHA3_512_BYTES }> {
                state: [0u64; ARR_SIZE],
                message: BitVec::new(),
            },
        }
    }
}

impl Hasher<{ SHA3_512_BYTES }> for Sha3_512 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        self.inner.update_bits(data);
    }

    fn finalize(&mut self, output: &mut [u8; SHA3_512_BYTES]) -> Result<()> {
        self.inner
            .finalize(output, SHA3_512_RATE, SHA3_512_CAPACITY)
    }
}

#[cfg(test)]
mod test {
    use bitvec::{bits, order::Lsb0};

    use crate::{
        Hasher, Sha3_512,
        constants::SHA3_512_BYTES,
        sha3::test::{Mode, create_test_vector, format_output},
    };

    const SHA3_512_0_BITS: &str = "A6 9F 73 CC A2 3A 9A C5 C8 B5 67 DC 18 5A 75 6E 97 C9 82 16 4F E2 58 59 E0 D1 DC C1 47 5C 80 A6 15 B2 12 3A F1 F5 F9 4C 11 E3 E9 40 2C 3A C5 58 F5 00 19 9D 95 B6 D3 E3 01 75 85 86 28 1D CD 26";
    const SHA3_512_5_BITS: &str = "A1 3E 01 49 41 14 C0 98 00 62 2A 70 28 8C 43 21 21 CE 70 03 9D 75 3C AD D2 E0 06 E4 D9 61 CB 27 54 4C 14 81 E5 81 4B DC EB 53 BE 67 33 D5 E0 99 79 5E 5E 81 91 8A DD B0 58 E2 2A 9F 24 88 3F 37";
    const SHA3_512_30_BITS: &str = "98 34 C0 5A 11 E1 C5 D3 DA 9C 74 0E 1C 10 6D 9E 59 0A 0E 53 0B 6F 6A AA 78 30 52 5D 07 5C A5 DB 1B D8 A6 AA 98 1A 28 61 3A C3 34 93 4A 01 82 3C D4 5F 45 E4 9B 6D 7E 69 17 F2 F1 67 78 06 7B AB";
    const SHA3_512_1600_BITS: &str = "E7 6D FA D2 20 84 A8 B1 46 7F CF 2F FA 58 36 1B EC 76 28 ED F5 F3 FD C0 E4 80 5D C4 8C AE EC A8 1B 7C 13 C3 0A DF 52 A3 65 95 84 73 9A 2D F4 6B E5 89 C5 1C A1 A4 A8 41 6D F6 54 5A 1C E8 BA 00";
    const SHA3_512_1605_BITS: &str = "FC 4A 16 7C CB 31 A9 37 D6 98 FD E8 2B 04 34 8C 95 39 B2 8F 0C 9D 3B 45 05 70 9C 03 81 23 50 E4 99 0E 96 22 97 4F 6E 57 5C 47 86 1C 0D 2E 63 8C CF C2 02 3C 36 5B B6 0A 93 F5 28 55 06 98 78 6B";
    const SHA3_512_1630_BITS: &str = "CF 9A 30 AC 1F 1F 6A C0 91 6F 9F EF 19 19 C5 95 DE BE 2E E8 0C 85 42 12 10 FD F0 5F 1C 6A F7 3A A9 CA C8 81 D0 F9 1D B6 D0 34 A2 BB AD C1 CF 7F BC B2 EC FA 9D 19 1D 3A 50 16 FB 3F AD 87 09 C9";

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg0.pdf>
    fn test_sha3_512_0_bits() {
        let mut hasher = Sha3_512::new();
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_0_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf>
    fn test_sha3_512_5_bits() {
        let mut hasher = Sha3_512::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1]);
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_5_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg30.pdf>
    fn test_sha3_512_30_bits() {
        let mut hasher = Sha3_512::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0]);
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_30_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf>
    fn test_sha3_512_1600_bits() {
        // Create 1600-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1600);
        assert_eq!(1600, bit_vec.len());
        let mut hasher = Sha3_512::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_1600_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1605.pdf>
    fn test_sha3_512_1605_bits() {
        // Create 1605-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1605);
        assert_eq!(1605, bit_vec.len());
        let mut hasher = Sha3_512::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_1605_BITS, format_output(&result));
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1630.pdf>
    fn test_sha3_512_1630_bits() {
        // Create 1630-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1630);
        assert_eq!(1630, bit_vec.len());
        let mut hasher = Sha3_512::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_512_BYTES];
        hasher.finalize(&mut result).unwrap();
        assert_eq!(SHA3_512_1630_BITS, format_output(&result));
    }
}
