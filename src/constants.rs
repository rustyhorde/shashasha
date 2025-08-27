// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::sync::LazyLock;

pub(crate) const SHA3_WIDTH: usize = 1600;
pub(crate) const SHA3_224_BITS: usize = 224;
pub(crate) const SHA3_224_BYTES: usize = SHA3_224_BITS / 8;
pub(crate) static SHA3_224_CAPACITY: LazyLock<usize> = LazyLock::new(|| 2 * SHA3_224_BITS);
pub(crate) static SHA3_224_RATE: LazyLock<usize> =
    LazyLock::new(|| SHA3_WIDTH - *SHA3_224_CAPACITY);

pub(crate) const ARR_SIZE: usize = 25;
pub(crate) const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
pub(crate) const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
pub(crate) const ROUND_CONSTS: [u64; 24] = [
    0x0_000_000_000_000_001,
    0x0_000_000_000_008_082,
    0x8_000_000_000_008_08a,
    0x8_000_000_080_008_000,
    0x0_000_000_000_008_08b,
    0x0_000_000_080_000_001,
    0x8_000_000_080_008_081,
    0x8_000_000_000_008_009,
    0x0_000_000_000_000_08a,
    0x0_000_000_000_000_088,
    0x0_000_000_080_008_009,
    0x0_000_000_080_000_00a,
    0x0_000_000_080_008_08b,
    0x8_000_000_000_000_08b,
    0x8_000_000_000_008_089,
    0x8_000_000_000_008_003,
    0x8_000_000_000_008_002,
    0x8_000_000_000_000_080,
    0x0_000_000_000_008_00a,
    0x8_000_000_080_000_00a,
    0x8_000_000_080_008_081,
    0x8_000_000_000_008_080,
    0x0_000_000_080_000_001,
    0x8_000_000_080_008_008,
];
