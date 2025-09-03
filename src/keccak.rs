// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! A Keccak implementation derived from <https://github.com/RustCrypto/sponges/tree/master/keccak>
//!

use crate::{
    Sha3Error,
    constants::{LANE_COUNT, PI, RHO, ROUND_CONSTS},
    lane::Lane,
};

use anyhow::Result;

/// Keccak-p permutation with width 200 (`Keccak-p[200, nr]`)
///
/// # Errors
///
/// If the round count is larger than the round count for the given lane an error will be thrown.
///
pub fn p_200(state: &mut [u8; LANE_COUNT], round_count: usize) -> Result<()> {
    keccak_p::<u8>(state, round_count)
}

/// Keccak-f permutation with width 200 (`Keccak-f[200]` = `Keccak-p[200, 18]`).
///
/// # Errors
///
/// If the round count is larger than the round count for the give lane an error will be thrown.
///
pub fn f_200(state: &mut [u8; LANE_COUNT]) -> Result<()> {
    p_200(state, u8::KECCAK_F_ROUND_COUNT)
}

/// Keccak-p permutation with width 400 (`Keccak-p[400, nr]`)
///
/// # Errors
///
/// If the round count is larger than the round count for the given lane an error will be thrown.
///
pub fn p_400(state: &mut [u16; LANE_COUNT], round_count: usize) -> Result<()> {
    keccak_p::<u16>(state, round_count)
}

/// Keccak-f permutation with width 400 (`Keccak-f[400]` = `Keccak-p[400, 20]`).
///
/// # Errors
///
/// If the round count is larger than the round count for the give lane an error will be thrown.
///
pub fn f_400(state: &mut [u16; LANE_COUNT]) -> Result<()> {
    p_400(state, u16::KECCAK_F_ROUND_COUNT)
}

/// Keccak-p permutation with width 800 (`Keccak-p[800, nr]`)
///
/// # Errors
///
/// If the round count is larger than the round count for the given lane an error will be thrown.
///
pub fn p_800(state: &mut [u32; LANE_COUNT], round_count: usize) -> Result<()> {
    keccak_p::<u32>(state, round_count)
}

/// Keccak-f permutation with width 800 (`Keccak-f[800]` = `Keccak-p[800, 22]`).
///
/// # Errors
///
/// If the round count is larger than the round count for the give lane an error will be thrown.
///
pub fn f_800(state: &mut [u32; LANE_COUNT]) -> Result<()> {
    p_800(state, u32::KECCAK_F_ROUND_COUNT)
}

/// Keccak-p permutation with width 1600 (`Keccak-p[1600, nr]`)
///
/// # Errors
///
/// If the round count is larger than the round count for the given lane an error will be thrown.
///
pub fn p_1600(state: &mut [u64; LANE_COUNT], round_count: usize) -> Result<()> {
    keccak_p::<u64>(state, round_count)
}

/// Keccak-f permutation with width 1600 (`Keccak-f[1600]` = `Keccak-p[1600, 24]`).
///
/// # Errors
///
/// If the round count is larger than the round count for the give lane an error will be thrown.
///
pub fn f_1600(state: &mut [u64; LANE_COUNT]) -> Result<()> {
    p_1600(state, u64::KECCAK_F_ROUND_COUNT)
}

#[cfg_attr(feature = "unroll", unroll::unroll_for_loops)]
#[cfg_attr(feature = "unroll", allow(unused_assignments))]
fn keccak_p<L: Lane>(state: &mut [L; LANE_COUNT], round_count: usize) -> Result<()> {
    if round_count <= L::KECCAK_F_ROUND_COUNT {
        let round_consts =
            &ROUND_CONSTS[(L::KECCAK_F_ROUND_COUNT - round_count)..L::KECCAK_F_ROUND_COUNT];

        for round_const in round_consts {
            let mut array = [L::default(); 5];

            for x in 0..5 {
                for y in 0..5 {
                    array[x] ^= state[5 * y + x];
                }
            }

            // Theta
            for x in 0..5 {
                let parity_1 = array[(x + 4) % 5];
                let parity_2 = array[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    state[5 * y + x] ^= parity_1 ^ parity_2;
                }
            }

            // Pi and Rho
            let mut last = state[1];
            for x in 0..24 {
                array[0] = state[PI[x]];
                state[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }

            // Chi
            for step in 0..5 {
                let y = 5 * step;
                array.copy_from_slice(&state[y..][..5]);

                for x in 0..5 {
                    let theta_1 = !array[(x + 1) % 5];
                    let theta_2 = array[(x + 2) % 5];
                    state[y + x] = array[x] ^ (theta_1 & theta_2);
                }
            }

            // Iota
            state[0] ^=
                L::truncate(*round_const).map_err(|_| Sha3Error::TruncateFailed(*round_const))?;
        }

        Ok(())
    } else {
        Err(Sha3Error::InvalidRoundCount(round_count).into())
    }
}

#[cfg(test)]
mod test {
    use crate::{constants::LANE_COUNT, f_200, f_400, f_800, f_1600};

    use super::keccak_p;

    use anyhow::Result;

    #[test]
    fn invalid_round_count_is_error() {
        assert!(keccak_p::<u8>(&mut [0u8; LANE_COUNT], 19).is_err());
        assert!(keccak_p::<u16>(&mut [0u16; LANE_COUNT], 21).is_err());
        assert!(keccak_p::<u32>(&mut [0u32; LANE_COUNT], 23).is_err());
        assert!(keccak_p::<u64>(&mut [0u64; LANE_COUNT], 25).is_err());
    }

    #[test]
    fn f_200_works() -> Result<()> {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-200-IntermediateValues.txt
        let state_first = [
            0x3C, 0x28, 0x26, 0x84, 0x1C, 0xB3, 0x5C, 0x17, 0x1E, 0xAA, 0xE9, 0xB8, 0x11, 0x13,
            0x4C, 0xEA, 0xA3, 0x85, 0x2C, 0x69, 0xD2, 0xC5, 0xAB, 0xAF, 0xEA,
        ];
        let state_second = [
            0x1B, 0xEF, 0x68, 0x94, 0x92, 0xA8, 0xA5, 0x43, 0xA5, 0x99, 0x9F, 0xDB, 0x83, 0x4E,
            0x31, 0x66, 0xA1, 0x4B, 0xE8, 0x27, 0xD9, 0x50, 0x40, 0x47, 0x9E,
        ];

        let mut state = [0u8; LANE_COUNT];
        f_200(&mut state)?;
        assert_eq!(state, state_first);
        f_200(&mut state)?;
        assert_eq!(state, state_second);
        Ok(())
    }

    #[test]
    fn f_400_works() -> Result<()> {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-400-IntermediateValues.txt
        let state_first = [
            0x09F5, 0x40AC, 0x0FA9, 0x14F5, 0xE89F, 0xECA0, 0x5BD1, 0x7870, 0xEFF0, 0xBF8F, 0x0337,
            0x6052, 0xDC75, 0x0EC9, 0xE776, 0x5246, 0x59A1, 0x5D81, 0x6D95, 0x6E14, 0x633E, 0x58EE,
            0x71FF, 0x714C, 0xB38E,
        ];
        let state_second = [
            0xE537, 0xD5D6, 0xDBE7, 0xAAF3, 0x9BC7, 0xCA7D, 0x86B2, 0xFDEC, 0x692C, 0x4E5B, 0x67B1,
            0x15AD, 0xA7F7, 0xA66F, 0x67FF, 0x3F8A, 0x2F99, 0xE2C2, 0x656B, 0x5F31, 0x5BA6, 0xCA29,
            0xC224, 0xB85C, 0x097C,
        ];

        let mut state = [0u16; LANE_COUNT];
        f_400(&mut state)?;
        assert_eq!(state, state_first);
        f_400(&mut state)?;
        assert_eq!(state, state_second);
        Ok(())
    }

    #[test]
    fn f_800_works() -> Result<()> {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt
        let state_first = [
            0xE5_31D_45D,
            0xF4_04C_6FB,
            0x23_A0B_F99,
            0xF1_F84_52F,
            0x51_FFD_042,
            0xE5_39F_578,
            0xF0_0B8_0A7,
            0xAF_973_664,
            0xBF_5AF_34C,
            0x22_7A2_424,
            0x88_172_715,
            0x9F_685_884,
            0xB1_5CD_054,
            0x1B_F4F_C0E,
            0x61_66F_A91,
            0x1A_9E5_99A,
            0xA3_970_A1F,
            0xAB_659_687,
            0xAF_AB8_D68,
            0xE7_4B1_015,
            0x34_001_A98,
            0x41_19E_FF3,
            0x93_0A0_E76,
            0x87_B28_070,
            0x11_EFE_996,
        ];
        let state_second = [
            0x75_BF2_D0D,
            0x9B_610_E89,
            0xC8_26A_F40,
            0x64_CD8_4AB,
            0xF9_05B_DD6,
            0xBC_832_835,
            0x5F_800_1B9,
            0x15_662_CCE,
            0x8E_38C_95E,
            0x70_1FE_543,
            0x1B_544_380,
            0x89_ACD_EFF,
            0x51_EDB_5DE,
            0x0E_970_2D9,
            0x6C_19A_A16,
            0xA2_913_EEE,
            0x60_754_E9A,
            0x98_190_63C,
            0xF4_709_254,
            0xD0_9F9_084,
            0x77_2DA_259,
            0x1D_B35_DF7,
            0x5A_A60_162,
            0x35_882_5D5,
            0xB3_783_BAB,
        ];

        let mut state = [0u32; LANE_COUNT];
        f_800(&mut state)?;
        assert_eq!(state, state_first);
        f_800(&mut state)?;
        assert_eq!(state, state_second);
        Ok(())
    }

    #[test]
    fn f_1600_works() -> Result<()> {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
        let state_first = [
            0xF_125_8F7_940_E1D_DE7,
            0x8_4D5_CCF_933_C04_78A,
            0xD_598_261_EA6_5AA_9EE,
            0xB_D15_473_06F_804_94D,
            0x8_B28_4E0_562_53D_057,
            0xF_F97_A42_D7F_8E6_FD4,
            0x9_0FE_E5A_0A4_464_7C4,
            0x8_C5B_DA0_CD6_192_E76,
            0xA_D30_A6F_71B_190_59C,
            0x3_093_5AB_7D0_8FF_C64,
            0xE_B5A_A93_F23_17D_635,
            0xA_9A6_E62_60D_712_103,
            0x8_1A5_7C1_6DB_CF5_55F,
            0x4_3B8_31C_D03_47C_826,
            0x0_1F2_2F1_A11_A55_69F,
            0x0_5E5_635_A21_D9A_E61,
            0x6_4BE_FEF_28C_C97_0F2,
            0x6_136_709_57B_C46_611,
            0xB_87C_5A5_54F_D00_ECB,
            0x8_C3E_E88_A1C_CF3_2C8,
            0x9_40C_792_2AE_3A2_614,
            0x1_841_F92_4A2_C50_9E4,
            0x1_6F5_352_6E7_046_5C2,
            0x7_5F6_44E_97F_30A_13B,
            0xE_AF1_FF7_B5C_ECA_249,
        ];
        let state_second = [
            0x2_D5C_954_DF9_6EC_B3C,
            0x6_A33_2CD_070_57B_56D,
            0x0_93D_8D1_270_D76_B6C,
            0x8_A20_D9B_255_69D_094,
            0x4_F9C_4F9_9E5_E7F_156,
            0xF_957_B9A_2DA_65F_B38,
            0x8_577_3DA_E12_75A_F0D,
            0xF_AF4_F24_7C3_D81_0F7,
            0x1_F1B_9EE_6F7_9A8_759,
            0xE_4FE_CC0_FEE_98B_425,
            0x6_8CE_61B_6B9_CE6_8A1,
            0xD_EEA_66C_4BA_8F9_74F,
            0x3_3C4_3D8_36E_AFB_1F5,
            0xE_006_540_427_19D_BD9,
            0x7_CF8_A9F_009_831_265,
            0xF_D54_49A_6BF_174_743,
            0x9_7DD_AD3_3D8_994_B40,
            0x4_8EA_D5F_C5D_0BE_774,
            0xE_3B8_C8E_E55_B7B_03C,
            0x9_1A0_226_E64_9E4_2E9,
            0x9_00E_312_9E7_BAD_D7B,
            0x2_02A_9EC_5FA_A3C_CE8,
            0x5_B34_024_64E_1C3_DB6,
            0x6_09F_4E6_2A4_4C1_059,
            0x2_0D0_6CD_26A_8FB_F5C,
        ];

        let mut state = [0u64; LANE_COUNT];
        f_1600(&mut state)?;
        assert_eq!(state, state_first);
        f_1600(&mut state)?;
        assert_eq!(state, state_second);
        Ok(())
    }
}
