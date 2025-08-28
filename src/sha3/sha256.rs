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
    constants::{SHA3_256_BYTES, SHA3_256_CAPACITY, SHA3_256_RATE},
    sha3::Sha3,
    sponge::Keccak1600Sponge,
};

/// SHA3-256 hash function (`SHA3-256(M) = KECCAK[512](M||01, 256)`)
#[derive(Clone, Debug)]
pub struct Sha3_256 {
    inner: Sha3<{ SHA3_256_BYTES }>,
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256 {
    /// Create a new SHA3-256 hasher instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3::<{ SHA3_256_BYTES }> {
                sponge: Keccak1600Sponge::new(SHA3_256_RATE, SHA3_256_CAPACITY),
            },
        }
    }
}

impl Hasher<{ SHA3_256_BYTES }> for Sha3_256 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        self.inner.update_bits(data);
    }

    fn finalize(&mut self, output: &mut [u8; SHA3_256_BYTES]) -> Result<()> {
        self.inner.finalize(output)
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use bitvec::{bits, order::Lsb0, vec::BitVec};

    use crate::{
        Hasher, Sha3_256, b2h,
        constants::SHA3_256_BYTES,
        test::{Mode, create_test_vector},
    };

    const SHA3_256_0_BITS: &str = "A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62 F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A";
    const SHA3_256_5_BITS: &str = "7B 00 47 CF 5A 45 68 82 36 3C BF 0F B0 53 22 CF 65 F4 B7 05 9A 46 36 5E 83 01 32 E3 B5 D9 57 AF";
    const SHA3_256_30_BITS: &str = "C8 24 2F EF 40 9E 5A E9 D1 F1 C8 57 AE 4D C6 24 B9 2B 19 80 9F 62 AA 8C 07 41 1C 54 A0 78 B1 D0";
    const SHA3_256_1600_BITS: &str = "79 F3 8A DE C5 C2 03 07 A9 8E F7 6E 83 24 AF BF D4 6C FD 81 B2 2E 39 73 C6 5F A1 BD 9D E3 17 87";
    const SHA3_256_1605_BITS: &str = "81 EE 76 9B ED 09 50 86 2B 1D DD ED 2E 84 AA A6 AB 7B FD D3 CE AA 47 1B E3 11 63 D4 03 36 36 3C";
    const SHA3_256_1630_BITS: &str = "52 86 0A A3 01 21 4C 61 0D 92 2A 6B 6C AB 98 1C CD 06 01 2E 54 EF 68 9D 74 40 21 E7 38 B9 ED 20";

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf>
    fn test_sha3_256_0_bits() -> Result<()> {
        let mut hasher = Sha3_256::new();
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_0_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg5.pdf>
    fn test_sha3_256_5_bits() -> Result<()> {
        let mut hasher = Sha3_256::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1]);
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_5_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg30.pdf>
    fn test_sha3_256_30_bits() -> Result<()> {
        let mut hasher = Sha3_256::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0]);
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_30_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf>
    fn test_sha3_256_1600_bits() -> Result<()> {
        // Create 1600-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1600);
        assert_eq!(1600, bit_vec.len());
        let mut hasher = Sha3_256::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_1600_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1605.pdf>
    fn test_sha3_256_1605_bits() -> Result<()> {
        // Create 1605-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1605);
        assert_eq!(1605, bit_vec.len());
        let mut hasher = Sha3_256::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_1605_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1630.pdf>
    fn test_sha3_256_1630_bits() -> Result<()> {
        // Create 1630-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1630);
        assert_eq!(1630, bit_vec.len());
        let mut hasher = Sha3_256::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; SHA3_256_BYTES];
        hasher.finalize(&mut result)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHA3_256_1630_BITS, res);
        Ok(())
    }
}
