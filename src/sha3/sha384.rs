// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bitvec::{order::Lsb0, slice::BitSlice};

use crate::{
    Hasher,
    constants::{SHA3_384_BYTES, SHA3_384_CAPACITY, SHA3_384_RATE},
    sha3::Sha3,
    sponge::Keccak1600Sponge,
};

/// SHA3-384 hash function (`SHA3-384(M) = KECCAK[768](M||01, 384)`)
#[derive(Clone, Debug)]
pub struct Sha3_384 {
    inner: Sha3<{ SHA3_384_BYTES }>,
}

impl Default for Sha3_384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_384 {
    /// Create a new SHA3-384 hasher instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3::<{ SHA3_384_BYTES }> {
                sponge: Keccak1600Sponge::new(SHA3_384_RATE, SHA3_384_CAPACITY),
            },
        }
    }
}

impl Hasher<{ SHA3_384_BYTES }> for Sha3_384 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        self.inner.update_bits(data);
    }

    fn finalize(&mut self, output: &mut [u8; SHA3_384_BYTES]) -> Result<()> {
        self.inner.finalize(output)
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use bitvec::{bits, order::Lsb0, vec::BitVec};

    use crate::{
        Hasher, Sha3_384, b2h,
        constants::SHA3_384_BYTES,
        test::{Mode, create_test_vector},
    };

    const SHA3_384_0_BITS: &str = "0C 63 A7 5B 84 5E 4F 7D 01 10 7D 85 2E 4C 24 85 C5 1A 50 AA AA 94 FC 61 99 5E 71 BB EE 98 3A 2A C3 71 38 31 26 4A DB 47 FB 6B D1 E0 58 D5 F0 04";
    const SHA3_384_5_BITS: &str = "73 7C 9B 49 18 85 E9 BF 74 28 E7 92 74 1A 7B F8 DC A9 65 34 71 C3 E1 48 47 3F 2C 23 6B 6A 0A 64 55 EB 1D CE 9F 77 9B 4B 6B 23 7F EF 17 1B 1C 64";
    const SHA3_384_30_BITS: &str = "95 5B 4D D1 BE 03 26 1B D7 6F 80 7A 7E FD 43 24 35 C4 17 36 28 11 B8 A5 0C 56 4E 7E E9 58 5E 1A C7 62 6D DE 2F DC 03 0F 87 61 96 EA 26 7F 08 C3";
    const SHA3_384_1600_BITS: &str = "18 81 DE 2C A7 E4 1E F9 5D C4 73 2B 8F 5F 00 2B 18 9C C1 E4 2B 74 16 8E D1 73 26 49 CE 1D BC DD 76 19 7A 31 FD 55 EE 98 9F 2D 70 50 DD 47 3E 8F";
    const SHA3_384_1605_BITS: &str = "A3 1F DB D8 D5 76 55 1C 21 FB 11 91 B5 4B DA 65 B6 C5 FE 97 F0 F4 A6 91 03 42 4B 43 F7 FD B8 35 97 9F DB EA E8 B3 FE 16 CB 82 E5 87 38 1E B6 24";
    const SHA3_384_1630_BITS: &str = "34 85 D3 B2 80 BD 38 4C F4 A7 77 84 4E 94 67 81 73 05 5D 1C BC 40 C7 C2 C3 83 3D 9E F1 23 45 17 2D 6F CD 31 92 3B B8 79 5A C8 18 47 D3 D8 85 5C";

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg0.pdf>
    fn test_sha3_384_0_bits() -> Result<()> {
        let mut hasher = Sha3_384::new();
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_0_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg5.pdf>
    fn test_sha3_384_5_bits() -> Result<()> {
        let mut hasher = Sha3_384::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1]);
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_5_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg30.pdf>
    fn test_sha3_384_30_bits() -> Result<()> {
        let mut hasher = Sha3_384::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0]);
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_30_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf>
    fn test_sha3_384_1600_bits() -> Result<()> {
        // Create 1600-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1600);
        assert_eq!(1600, bit_vec.len());
        let mut hasher = Sha3_384::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_1600_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1605.pdf>
    fn test_sha3_384_1605_bits() -> Result<()> {
        // Create 1605-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1605);
        assert_eq!(1605, bit_vec.len());
        let mut hasher = Sha3_384::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_1605_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1630.pdf>
    fn test_sha3_384_1630_bits() -> Result<()> {
        // Create 1630-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1630);
        assert_eq!(1630, bit_vec.len());
        let mut hasher = Sha3_384::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_384_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_384_1630_BITS, res);
        Ok(())
    }
}
