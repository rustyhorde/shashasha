// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::fmt::Write;

use anyhow::Result;
use bitvec::{field::BitField, order::Lsb0, vec::BitVec};

/// bits to hex conversion defined at section B.1 in <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>
///
/// # Errors
/// The [`write!`] macro can throw I/O errors.
///
pub fn b2h(bits: &BitVec<u8, Lsb0>, include_space: bool, upper: bool) -> Result<String> {
    let mut res = String::new();
    let mut chunks = bits.chunks_exact(8);
    for byte in &mut chunks {
        let value: u8 = byte.load_le::<u8>();
        if upper {
            write!(res, "{value:02X}")?;
        } else {
            write!(res, "{value:02x}")?;
        }
        if include_space {
            res.push(' ');
        }
    }

    let mut rem = chunks.remainder().to_bitvec();

    if !rem.is_empty() {
        for _ in 0..8 - rem.len() {
            rem.push(false);
        }
        let value: u8 = rem.load_le::<u8>();
        if upper {
            write!(res, "{value:02X}")?;
        } else {
            write!(res, "{value:02x}")?;
        }
        if include_space {
            res.push(' ');
        }
    }
    Ok(res.trim_end().to_string())
}

#[cfg(test)]
mod test {
    use super::b2h;

    use anyhow::Result;

    use crate::{Lsb0, bitvec};

    #[test]
    fn test_b2h_incude_space_upper() -> Result<()> {
        let bits = bitvec![u8, Lsb0; 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0];
        let hex = b2h(&bits, true, true)?;
        assert_eq!(hex, "AA 55");
        Ok(())
    }

    #[test]
    fn test_b2h_no_space_upper() -> Result<()> {
        let bits = bitvec![u8, Lsb0; 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0];
        let hex = b2h(&bits, false, true)?;
        assert_eq!(hex, "AA55");
        Ok(())
    }

    #[test]
    fn test_b2h_incude_space_lower() -> Result<()> {
        let bits = bitvec![u8, Lsb0; 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0];
        let hex = b2h(&bits, true, false)?;
        assert_eq!(hex, "aa 55");
        Ok(())
    }

    #[test]
    fn test_b2h_no_space_lower() -> Result<()> {
        let bits = bitvec![u8, Lsb0; 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0];
        let hex = b2h(&bits, false, false)?;
        assert_eq!(hex, "aa55");
        Ok(())
    }
}
