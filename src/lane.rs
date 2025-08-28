// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! A Keccak lane trait

use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign, Not},
};

use anyhow::Result;

/// A Keccak lane
pub(crate) trait Lane:
    Copy
    + Clone
    + Debug
    + Default
    + PartialEq
    + BitAndAssign
    + BitAnd<Output = Self>
    + BitXorAssign
    + BitXor<Output = Self>
    + Not<Output = Self>
{
    /// The round count for this lane size
    const KECCAK_F_ROUND_COUNT: usize;
    /// The `truncate` function for this lane size
    ///
    /// # Errors
    ///
    /// An error can be thrown if the round constant cannot be properly truncated.
    ///
    fn truncate(round_constant: u64) -> Result<Self>;
    /// The `rotate_left` function for this lane size
    #[must_use]
    fn rotate_left(self, num_bits: u32) -> Self;
}

impl Lane for u8 {
    const KECCAK_F_ROUND_COUNT: usize = 18;

    fn truncate(round_constant: u64) -> Result<Self> {
        Ok(round_constant.to_le_bytes()[0])
    }

    fn rotate_left(self, num_bits: u32) -> Self {
        self.rotate_left(num_bits)
    }
}

impl Lane for u16 {
    const KECCAK_F_ROUND_COUNT: usize = 20;

    fn truncate(round_constant: u64) -> Result<Self> {
        let tmp = round_constant.to_le_bytes();
        Ok(Self::from_le_bytes(tmp[..size_of::<Self>()].try_into()?))
    }

    fn rotate_left(self, num_bits: u32) -> Self {
        self.rotate_left(num_bits)
    }
}

impl Lane for u32 {
    const KECCAK_F_ROUND_COUNT: usize = 22;

    fn truncate(round_constant: u64) -> Result<Self> {
        let tmp = round_constant.to_le_bytes();
        Ok(Self::from_le_bytes(tmp[..size_of::<Self>()].try_into()?))
    }

    fn rotate_left(self, num_bits: u32) -> Self {
        self.rotate_left(num_bits)
    }
}

impl Lane for u64 {
    const KECCAK_F_ROUND_COUNT: usize = 24;

    fn truncate(round_constant: u64) -> Result<Self> {
        Ok(round_constant)
    }

    fn rotate_left(self, num_bits: u32) -> Self {
        self.rotate_left(num_bits)
    }
}
