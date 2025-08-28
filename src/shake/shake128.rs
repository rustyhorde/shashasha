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
    XofHasher,
    constants::{SHAKE_128_CAPACITY, SHAKE_128_RATE},
    shake::Shake,
    sponge::Keccak1600Sponge,
};

/// SHAKE128 XOF function (`SHAKE128(M, d) = KECCAK[256](M||1111, d)`)
#[derive(Clone, Debug)]
pub struct Shake128 {
    inner: Shake,
}

impl Shake128 {
    /// Create a new SHAKE128 XOF hasher instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Shake {
                sponge: Keccak1600Sponge::new(SHAKE_128_RATE, SHAKE_128_CAPACITY),
            },
        }
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl XofHasher for Shake128 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn update_bits(&mut self, data: &BitSlice<u8, Lsb0>) {
        self.inner.update_bits(data);
    }

    fn finalize(&mut self) -> Result<()> {
        self.inner.finalize()
    }

    fn get_bytes(&mut self, output: &mut [u8], num_bytes: usize) -> Result<()> {
        self.inner.get_bytes(output, num_bytes)
    }

    fn get_bits(&mut self, output: &mut BitVec<u8, Lsb0>, num_bits: usize) -> Result<()> {
        self.inner.get_bits(output, num_bits)
    }
}

#[cfg(test)]
mod test {
    use anyhow::{Ok, Result};
    use bitvec::{bits, order::Lsb0, vec::BitVec};

    use crate::{
        Shake128, XofHasher, b2h,
        test::{Mode, create_test_vector},
    };

    const NUM_BITS: usize = 4096;
    const NUM_BYTES: usize = NUM_BITS / 8;
    const SHAKE128_0_BITS: &str = "7F 9C 2B A4 E8 8F 82 7D 61 60 45 50 76 05 85 3E \
D7 3B 80 93 F6 EF BC 88 EB 1A 6E AC FA 66 EF 26 \
3C B1 EE A9 88 00 4B 93 10 3C FB 0A EE FD 2A 68 \
6E 01 FA 4A 58 E8 A3 63 9C A8 A1 E3 F9 AE 57 E2 \
35 B8 CC 87 3C 23 DC 62 B8 D2 60 16 9A FA 2F 75 \
AB 91 6A 58 D9 74 91 88 35 D2 5E 6A 43 50 85 B2 \
BA DF D6 DF AA C3 59 A5 EF BB 7B CC 4B 59 D5 38 \
DF 9A 04 30 2E 10 C8 BC 1C BF 1A 0B 3A 51 20 EA \
17 CD A7 CF AD 76 5F 56 23 47 4D 36 8C CC A8 AF \
00 07 CD 9F 5E 4C 84 9F 16 7A 58 0B 14 AA BD EF \
AE E7 EE F4 7C B0 FC A9 76 7B E1 FD A6 94 19 DF \
B9 27 E9 DF 07 34 8B 19 66 91 AB AE B5 80 B3 2D \
EF 58 53 8B 8D 23 F8 77 32 EA 63 B0 2B 4F A0 F4 \
87 33 60 E2 84 19 28 CD 60 DD 4C EE 8C C0 D4 C9 \
22 A9 61 88 D0 32 67 5C 8A C8 50 93 3C 7A FF 15 \
33 B9 4C 83 4A DB B6 9C 61 15 BA D4 69 2D 86 19 \
F9 0B 0C DF 8A 7B 9C 26 40 29 AC 18 5B 70 B8 3F \
28 01 F2 F4 B3 F7 0C 59 3E A3 AE EB 61 3A 7F 1B \
1D E3 3F D7 50 81 F5 92 30 5F 2E 45 26 ED C0 96 \
31 B1 09 58 F4 64 D8 89 F3 1B A0 10 25 0F DA 7F \
13 68 EC 29 67 FC 84 EF 2A E9 AF F2 68 E0 B1 70 \
0A FF C6 82 0B 52 3A 3D 91 71 35 F2 DF F2 EE 06 \
BF E7 2B 31 24 72 1D 4A 26 C0 4E 53 A7 5E 30 E7 \
3A 7A 9C 4A 95 D9 1C 55 D4 95 E9 F5 1D D0 B5 E9 \
D8 3C 6D 5E 8C E8 03 AA 62 B8 D6 54 DB 53 D0 9B \
8D CF F2 73 CD FE B5 73 FA D8 BC D4 55 78 BE C2 \
E7 70 D0 1E FD E8 6E 72 1A 3F 7C 6C CE 27 5D AB \
E6 E2 14 3F 1A F1 8D A7 EF DD C4 C7 B7 0B 5E 34 \
5D B9 3C C9 36 BE A3 23 49 1C CB 38 A3 88 F5 46 \
A9 FF 00 DD 4E 13 00 B9 B2 15 3D 20 41 D2 05 B4 \
43 E4 1B 45 A6 53 F2 A5 C4 49 2C 1A DD 54 45 12 \
DD A2 52 98 33 46 2B 71 A4 1A 45 BE 97 29 0B 6F";
    const SHAKE128_0_BITS_2048: &str = "7F 9C 2B A4 E8 8F 82 7D 61 60 45 50 76 05 85 3E \
D7 3B 80 93 F6 EF BC 88 EB 1A 6E AC FA 66 EF 26 \
3C B1 EE A9 88 00 4B 93 10 3C FB 0A EE FD 2A 68 \
6E 01 FA 4A 58 E8 A3 63 9C A8 A1 E3 F9 AE 57 E2 \
35 B8 CC 87 3C 23 DC 62 B8 D2 60 16 9A FA 2F 75 \
AB 91 6A 58 D9 74 91 88 35 D2 5E 6A 43 50 85 B2 \
BA DF D6 DF AA C3 59 A5 EF BB 7B CC 4B 59 D5 38 \
DF 9A 04 30 2E 10 C8 BC 1C BF 1A 0B 3A 51 20 EA \
17 CD A7 CF AD 76 5F 56 23 47 4D 36 8C CC A8 AF \
00 07 CD 9F 5E 4C 84 9F 16 7A 58 0B 14 AA BD EF \
AE E7 EE F4 7C B0 FC A9 76 7B E1 FD A6 94 19 DF \
B9 27 E9 DF 07 34 8B 19 66 91 AB AE B5 80 B3 2D \
EF 58 53 8B 8D 23 F8 77 32 EA 63 B0 2B 4F A0 F4 \
87 33 60 E2 84 19 28 CD 60 DD 4C EE 8C C0 D4 C9 \
22 A9 61 88 D0 32 67 5C 8A C8 50 93 3C 7A FF 15 \
33 B9 4C 83 4A DB B6 9C 61 15 BA D4 69 2D 86 19";
    const SHAKE128_0_BITS_4094: &str = "7F 9C 2B A4 E8 8F 82 7D 61 60 45 50 76 05 85 3E \
D7 3B 80 93 F6 EF BC 88 EB 1A 6E AC FA 66 EF 26 \
3C B1 EE A9 88 00 4B 93 10 3C FB 0A EE FD 2A 68 \
6E 01 FA 4A 58 E8 A3 63 9C A8 A1 E3 F9 AE 57 E2 \
35 B8 CC 87 3C 23 DC 62 B8 D2 60 16 9A FA 2F 75 \
AB 91 6A 58 D9 74 91 88 35 D2 5E 6A 43 50 85 B2 \
BA DF D6 DF AA C3 59 A5 EF BB 7B CC 4B 59 D5 38 \
DF 9A 04 30 2E 10 C8 BC 1C BF 1A 0B 3A 51 20 EA \
17 CD A7 CF AD 76 5F 56 23 47 4D 36 8C CC A8 AF \
00 07 CD 9F 5E 4C 84 9F 16 7A 58 0B 14 AA BD EF \
AE E7 EE F4 7C B0 FC A9 76 7B E1 FD A6 94 19 DF \
B9 27 E9 DF 07 34 8B 19 66 91 AB AE B5 80 B3 2D \
EF 58 53 8B 8D 23 F8 77 32 EA 63 B0 2B 4F A0 F4 \
87 33 60 E2 84 19 28 CD 60 DD 4C EE 8C C0 D4 C9 \
22 A9 61 88 D0 32 67 5C 8A C8 50 93 3C 7A FF 15 \
33 B9 4C 83 4A DB B6 9C 61 15 BA D4 69 2D 86 19 \
F9 0B 0C DF 8A 7B 9C 26 40 29 AC 18 5B 70 B8 3F \
28 01 F2 F4 B3 F7 0C 59 3E A3 AE EB 61 3A 7F 1B \
1D E3 3F D7 50 81 F5 92 30 5F 2E 45 26 ED C0 96 \
31 B1 09 58 F4 64 D8 89 F3 1B A0 10 25 0F DA 7F \
13 68 EC 29 67 FC 84 EF 2A E9 AF F2 68 E0 B1 70 \
0A FF C6 82 0B 52 3A 3D 91 71 35 F2 DF F2 EE 06 \
BF E7 2B 31 24 72 1D 4A 26 C0 4E 53 A7 5E 30 E7 \
3A 7A 9C 4A 95 D9 1C 55 D4 95 E9 F5 1D D0 B5 E9 \
D8 3C 6D 5E 8C E8 03 AA 62 B8 D6 54 DB 53 D0 9B \
8D CF F2 73 CD FE B5 73 FA D8 BC D4 55 78 BE C2 \
E7 70 D0 1E FD E8 6E 72 1A 3F 7C 6C CE 27 5D AB \
E6 E2 14 3F 1A F1 8D A7 EF DD C4 C7 B7 0B 5E 34 \
5D B9 3C C9 36 BE A3 23 49 1C CB 38 A3 88 F5 46 \
A9 FF 00 DD 4E 13 00 B9 B2 15 3D 20 41 D2 05 B4 \
43 E4 1B 45 A6 53 F2 A5 C4 49 2C 1A DD 54 45 12 \
DD A2 52 98 33 46 2B 71 A4 1A 45 BE 97 29 0B 2F";
    const SHAKE128_0_BITS_4088: &str = "7F 9C 2B A4 E8 8F 82 7D 61 60 45 50 76 05 85 3E \
D7 3B 80 93 F6 EF BC 88 EB 1A 6E AC FA 66 EF 26 \
3C B1 EE A9 88 00 4B 93 10 3C FB 0A EE FD 2A 68 \
6E 01 FA 4A 58 E8 A3 63 9C A8 A1 E3 F9 AE 57 E2 \
35 B8 CC 87 3C 23 DC 62 B8 D2 60 16 9A FA 2F 75 \
AB 91 6A 58 D9 74 91 88 35 D2 5E 6A 43 50 85 B2 \
BA DF D6 DF AA C3 59 A5 EF BB 7B CC 4B 59 D5 38 \
DF 9A 04 30 2E 10 C8 BC 1C BF 1A 0B 3A 51 20 EA \
17 CD A7 CF AD 76 5F 56 23 47 4D 36 8C CC A8 AF \
00 07 CD 9F 5E 4C 84 9F 16 7A 58 0B 14 AA BD EF \
AE E7 EE F4 7C B0 FC A9 76 7B E1 FD A6 94 19 DF \
B9 27 E9 DF 07 34 8B 19 66 91 AB AE B5 80 B3 2D \
EF 58 53 8B 8D 23 F8 77 32 EA 63 B0 2B 4F A0 F4 \
87 33 60 E2 84 19 28 CD 60 DD 4C EE 8C C0 D4 C9 \
22 A9 61 88 D0 32 67 5C 8A C8 50 93 3C 7A FF 15 \
33 B9 4C 83 4A DB B6 9C 61 15 BA D4 69 2D 86 19 \
F9 0B 0C DF 8A 7B 9C 26 40 29 AC 18 5B 70 B8 3F \
28 01 F2 F4 B3 F7 0C 59 3E A3 AE EB 61 3A 7F 1B \
1D E3 3F D7 50 81 F5 92 30 5F 2E 45 26 ED C0 96 \
31 B1 09 58 F4 64 D8 89 F3 1B A0 10 25 0F DA 7F \
13 68 EC 29 67 FC 84 EF 2A E9 AF F2 68 E0 B1 70 \
0A FF C6 82 0B 52 3A 3D 91 71 35 F2 DF F2 EE 06 \
BF E7 2B 31 24 72 1D 4A 26 C0 4E 53 A7 5E 30 E7 \
3A 7A 9C 4A 95 D9 1C 55 D4 95 E9 F5 1D D0 B5 E9 \
D8 3C 6D 5E 8C E8 03 AA 62 B8 D6 54 DB 53 D0 9B \
8D CF F2 73 CD FE B5 73 FA D8 BC D4 55 78 BE C2 \
E7 70 D0 1E FD E8 6E 72 1A 3F 7C 6C CE 27 5D AB \
E6 E2 14 3F 1A F1 8D A7 EF DD C4 C7 B7 0B 5E 34 \
5D B9 3C C9 36 BE A3 23 49 1C CB 38 A3 88 F5 46 \
A9 FF 00 DD 4E 13 00 B9 B2 15 3D 20 41 D2 05 B4 \
43 E4 1B 45 A6 53 F2 A5 C4 49 2C 1A DD 54 45 12 \
DD A2 52 98 33 46 2B 71 A4 1A 45 BE 97 29 0B";
    const SHAKE128_5_BITS: &str = "2E 0A BF BA 83 E6 72 0B FB C2 25 FF 6B 7A B9 FF \
CE 58 BA 02 7E E3 D8 98 76 4F EF 28 7D DE CC CA \
3E 6E 59 98 41 1E 7D DB 32 F6 75 38 F5 00 B1 8C \
8C 97 C4 52 C3 70 EA 2C F0 AF CA 3E 05 DE 7E 4D \
E2 7F A4 41 A9 CB 34 FD 17 C9 78 B4 2D 5B 7E 7F \
9A B1 8F FE FF C3 C5 AC 2F 3A 45 5E EB FD C7 6C \
EA EB 0A 2C CA 22 EE F6 E6 37 F4 CA BE 5C 51 DE \
D2 E3 FA D8 B9 52 70 A3 21 84 56 64 F1 07 D1 64 \
96 BB 7A BF BE 75 04 B6 ED E2 E8 9E 4B 99 6F B5 \
8E FD C4 18 1F 91 63 38 1C BE 7B C0 06 A7 A2 05 \
98 9C 52 6C D1 BD 68 98 36 93 B4 BD C5 37 28 B2 \
41 C1 CF F4 2B B6 11 50 2C 35 20 5C AB B2 88 75 \
56 55 D6 20 C6 79 94 F0 64 51 18 7F 6F D1 7E 04 \
66 82 BA 12 86 06 3F F8 8F E2 50 8D 1F CA F9 03 \
5A 12 31 AD 41 50 A9 C9 B2 4C 9B 2D 66 B2 AD 1B \
DE 0B D0 BB CB 8B E0 5B 83 52 29 EF 79 19 73 73 \
23 42 44 01 E1 D8 37 B6 6E B4 E6 30 FF 1D E7 0C \
B3 17 C2 BA CB 08 00 1D 34 77 B7 A7 0A 57 6D 20 \
86 90 33 58 9D 85 A0 1D DB 2B 66 46 C0 43 B5 9F \
C0 11 31 1D A6 66 FA 5A D1 D6 38 7F A9 BC 40 15 \
A3 8A 51 D1 DA 1E A6 1D 64 8D C8 E3 9A 88 B9 D6 \
22 BD E2 07 FD AB C6 F2 82 7A 88 0C 33 0B BF 6D \
F7 33 77 4B 65 3E 57 30 5D 78 DC E1 12 F1 0A 2C \
71 F4 CD AD 92 ED 11 3E 1C EA 63 B9 19 25 ED 28 \
19 1E 6D BB B5 AA 5A 2A FD A5 1F C0 5A 3A F5 25 \
8B 87 66 52 43 55 0F 28 94 8A E2 B8 BE B6 BC 9C \
77 0B 35 F0 67 EA A6 41 EF E6 5B 1A 44 90 9D 1B \
14 9F 97 EE A6 01 39 1C 60 9E C8 1D 19 30 F5 7C \
18 A4 E0 FA B4 91 D1 CA DF D5 04 83 44 9E DC 0F \
07 FF B2 4D 2C 6F 9A 9A 3B FF 39 AE 3D 57 F5 60 \
65 4D 7D 75 C9 08 AB E6 25 64 75 3E AC 39 D7 50 \
3D A6 D3 7C 2E 32 E1 AF 3B 8A EC 8A E3 06 9C D9";
    const SHAKE128_30_BITS: &str = "6D 5D 39 C5 5F 3C CA 56 7F EA F4 22 DC 64 BA 17 \
40 1D 07 75 6D 78 B0 FA 3D 54 6D 66 AF C2 76 71 \
E0 01 06 85 FC 69 A7 EC 3C 53 67 B8 FA 5F DA 39 \
D5 7C E5 3F 15 3F A4 03 1D 27 72 06 77 0A EC 6B \
2D DF 16 AE FA B6 69 11 0D 6E 4A 29 6A 14 FB 14 \
86 B0 84 6B 69 05 43 E4 05 7F 7F 42 AA 8C 0E 6A \
5A 56 B6 0B 68 8D 55 A1 96 DF 6F 39 76 E3 06 88 \
CB B6 AF D4 85 25 D7 64 90 35 7F 3F D8 97 BA FC \
87 36 D9 07 B9 BA C8 16 59 1F C2 4E 79 36 0B E3 \
A7 FF A6 29 82 C4 5A BB 0E 58 4C 07 EC 93 A1 95 \
30 50 9D 9F 81 62 15 D7 27 7B B9 99 43 7C 82 14 \
50 F0 75 92 81 CD 8E 16 A3 48 3E 3C C7 52 09 1B \
7A AE 92 90 9D 2F 50 1E F7 DC E9 89 75 98 91 B3 \
37 7C EA B4 93 FF E4 96 01 0A 0C 7E 51 95 99 94 \
F5 6F 56 5E 63 3A F6 09 3A C6 E1 E0 F0 04 88 71 \
EC 47 78 F4 8E F8 BD 5B CB 80 EA 7D F9 FF 47 11 \
C8 1E 24 C0 22 1C 2A D9 74 4F BA 79 35 EA EC A1 \
14 22 4F D1 08 EF C5 AC 74 C6 62 52 08 92 75 B4 \
27 76 73 70 8C 4A F9 2F 88 13 B1 93 59 9F D6 4B \
D7 48 4F 2E 5E C3 69 E3 64 64 99 76 8E 58 1D D0 \
53 AA 48 14 D8 BF 1A CF F5 FD 77 45 19 A7 49 BE \
66 75 47 41 EB C5 36 22 12 A9 FE A8 A8 14 E9 E0 \
10 BC 27 20 B3 B7 D9 4F AB 74 BC 7F 92 3E 10 72 \
B8 A5 DD DD A8 3B A0 15 7D 8C BA 55 C1 92 DF 69 \
65 CB 7D BA 46 A3 34 0D F8 C3 FA 89 C7 C4 DB 53 \
9D 38 DC 40 6F 1D 2C F5 4E 59 05 58 0B 44 04 BF \
D7 B3 71 95 61 C5 A5 9D 5D FD B1 BF 93 DF 13 82 \
52 25 ED CC E0 FA 7D 87 EF CD 23 9F EB 49 FC 9E \
2D E9 D8 28 FE EB 1F 2C F5 79 B9 5D D0 50 AB 2C \
A4 71 05 A8 D3 0F 3F D2 A1 15 4C 15 F8 7F B3 7B \
2C 71 56 BD 7F 3C F2 B7 45 C9 12 A4 0B C1 B5 59 \
B6 56 E3 E9 03 CC 57 33 E8 6B A1 5D FE F7 06 78";
    const SHAKE128_1600_BITS: &str = "13 1A B8 D2 B5 94 94 6B 9C 81 33 3F 9B B6 E0 CE \
75 C3 B9 31 04 FA 34 69 D3 91 74 57 38 5D A0 37 \
CF 23 2E F7 16 4A 6D 1E B4 48 C8 90 81 86 AD 85 \
2D 3F 85 A5 CF 28 DA 1A B6 FE 34 38 17 19 78 46 \
7F 1C 05 D5 8C 7E F3 8C 28 4C 41 F6 C2 22 1A 76 \
F1 2A B1 C0 40 82 66 02 50 80 22 94 FB 87 18 02 \
13 FD EF 5B 0E CB 7D F5 0C A1 F8 55 5B E1 4D 32 \
E1 0F 6E DC DE 89 2C 09 42 4B 29 F5 97 AF C2 70 \
C9 04 55 6B FC B4 7A 7D 40 77 8D 39 09 23 64 2B \
3C BD 05 79 E6 09 08 D5 A0 00 C1 D0 8B 98 EF 93 \
3F 80 64 45 BF 87 F8 B0 09 BA 9E 94 F7 26 61 22 \
ED 7A C2 4E 5E 26 6C 42 A8 2F A1 BB EF B7 B8 DB \
00 66 E1 6A 85 E0 49 3F 07 DF 48 09 AE C0 84 A5 \
93 74 8A C3 DD E5 A6 D7 AA E1 E8 B6 E5 35 2B 2D \
71 EF BB 47 D4 CA EE D5 E6 D6 33 80 5D 2D 32 3E \
6F D8 1B 46 84 B9 3A 26 77 D4 5E 74 21 C2 C6 AE \
A2 59 B8 55 A6 98 FD 7D 13 47 7A 1F E5 3E 5A 4A \
61 97 DB EC 5C E9 5F 50 5B 52 0B CD 95 70 C4 A8 \
26 5A 7E 01 F8 9C 0C 00 2C 59 BF EC 6C D4 A5 C1 \
09 25 89 53 EE 5E E7 0C D5 77 EE 21 7A F2 1F A7 \
01 78 F0 94 6C 9B F6 CA 87 51 79 34 79 F6 B5 37 \
73 7E 40 B6 ED 28 51 1D 8A 2D 7E 73 EB 75 F8 DA \
AC 91 2F F9 06 E0 AB 95 5B 08 3B AC 45 A8 E5 E9 \
B7 44 C8 50 6F 37 E9 B4 E7 49 A1 84 B3 0F 43 EB \
18 8D 85 5F 1B 70 D7 1F F3 E5 0C 53 7A C1 B0 F8 \
97 4F 0F E1 A6 AD 29 5B A4 2F 6A EC 74 D1 23 A7 \
AB ED DE 6E 2C 07 11 CA B3 6B E5 AC B1 A5 A1 1A \
4B 1D B0 8B A6 98 2E FC CD 71 69 29 A7 74 1C FC \
63 AA 44 35 E0 B6 9A 90 63 E8 80 79 5C 3D C5 EF \
32 72 E1 1C 49 7A 91 AC F6 99 FE FE E2 06 22 7A \
44 C9 FB 35 9F D5 6A C0 A9 A7 5A 74 3C FF 68 62 \
F1 7D 72 59 AB 07 52 16 C0 69 95 11 64 3B 64 39";
    const SHAKE128_1605_BITS: &str = "4A C3 8E BD 16 78 B4 A4 52 79 2C 56 73 F9 77 7D \
36 B5 54 51 AA AE 24 24 92 49 42 D3 18 A2 F6 F5 \
1B BC 83 7D CC 70 22 C5 40 3B 69 D2 9A C9 9A 74 \
5F 06 D0 6F 2A 41 B0 CC 24 3C D2 70 FA 44 D4 30 \
65 AF 00 D2 AD 35 8B D5 A5 D0 6D 33 1B C2 30 CD \
8D DA 46 55 62 8F 91 02 71 1A DA FB 76 36 C1 60 \
B2 D2 5E C6 23 5A 2F E0 F3 73 94 D8 7F C5 FF D7 \
DB F1 99 3E 55 8A EB EA 6C 61 E9 07 18 8C 61 F5 \
FC DE 27 8E 26 4F 95 8F FD 7B 33 82 DC 10 13 9B \
62 5E 12 41 AB 5B BC 2A 1F BC AC 31 A3 35 CF C7 \
B2 0E 42 77 12 24 6C BB 55 23 22 59 A7 EF 16 02 \
BD 56 F6 56 7D 66 94 2D 4A 71 49 F4 22 22 10 B0 \
74 EA 54 15 4B 38 E8 FD FA 0D CF 4F A3 EC D2 15 \
4E 83 18 A6 57 8B 53 5D BC FC 21 7A 3C AB 52 53 \
29 65 84 6F 89 78 14 57 02 55 63 E2 DC 15 CC 3A \
F9 02 BA 2A D2 80 FF BB BF A4 C5 2B 60 FA 41 BA \
C2 1F 4A B2 35 36 26 81 19 FC 98 CD 98 2D A5 CD \
5D A2 1E 1B 56 92 D4 71 05 DE 9F 1E 01 32 C6 FE \
31 5D 67 FA 46 49 97 C2 AB 55 33 C7 9F 98 E6 E6 \
4F F8 08 02 A7 FE 96 CA 04 A8 1F 88 55 27 37 0A \
22 06 B1 0B 39 36 DD 81 B8 24 63 53 F4 CD 90 51 \
10 89 26 8D 74 4F 21 0A C6 89 D4 9D 28 75 05 4A \
72 7B 60 4D 13 D2 69 B3 71 90 D4 27 C7 D1 5C CC \
DC D7 87 0E 0B 8A DB EB 97 71 11 A9 BC F7 78 1A \
16 13 56 A5 94 1C 79 99 07 EF 9D 3B 1A 44 1F 09 \
51 5F 28 31 C4 FA FD E3 DC 7C 1E 9B 5A A5 7D 3E \
83 CD 67 34 DA 3D 8B 9E F3 FC 44 88 05 EA 29 C9 \
9C BA 6B 35 2B CA BE 2F D9 70 AE 95 80 D2 BF 25 \
15 2B 96 0E 6B 80 6D 87 D7 D0 60 8B 24 7F 61 08 \
9E 29 86 92 C2 7F 19 C5 2D 03 EB E3 95 A3 68 06 \
AD 54 0B EC 2D 04 6C 18 E3 55 FA F8 31 3D 2E F8 \
99 5E E6 AA E4 25 68 F3 14 93 3E 3A 21 E5 BE 40";
    const SHAKE128_1630_BITS: &str = "89 84 6D C7 76 AC 0F 01 45 72 EA 79 F5 60 77 34 \
51 00 29 38 24 8E 68 82 56 9A C3 2A EA B1 91 FC \
AC DE 68 EB 07 55 75 39 C4 84 5F B4 44 10 8E 6E \
05 45 E7 31 FC CA 2D 4F 67 A3 BF D4 1C FF 3E AF \
35 EE FB 53 44 11 77 96 5B B5 16 95 0C F5 DC B2 \
AA FC BB C6 30 0E 8E EF D9 BC D0 E5 F3 2D 1A 4E \
87 2E 0F 1D BD 8F 8E 00 CB B8 78 69 8C 58 83 E3 \
CA 18 4B 94 90 38 9E 46 00 2C 08 A0 B1 6B 05 A3 \
6B 2C B5 A1 CA E0 8E 11 AD 97 2F D2 4A F7 01 01 \
CE 47 46 C8 4F 16 71 87 7F 0D F6 C4 15 D1 67 0F \
F4 0B 8D DE DD 89 CC 3E 65 6D B9 05 80 49 D6 09 \
B6 78 4C C9 D0 5E 60 CC 6A C9 C8 19 49 93 BA 29 \
15 8F D4 DB 8C F2 25 E9 57 4F 18 A7 7F 66 EC 10 \
52 BF 17 99 3B DA 20 6A 17 73 7D 78 5B D4 C1 8C \
EE 4C 76 AA 57 35 A5 22 3F 3C 55 E7 9D AE C1 3D \
4B F6 0F 15 62 E0 AD 0F A3 B5 58 EC CF A8 AB 3E \
EF 61 47 4D 57 6E 8C AF 4C 11 E4 DE 5C CB 36 D7 \
DF 7D 89 2C 1F CA 20 17 BE 8B BD A5 A4 71 95 44 \
8C C6 7A 07 8E 62 8A 2E F7 63 FF E1 DC 9D 9D 6F \
F7 8E 68 96 1C 33 FF D9 00 0C 11 DE E7 F7 40 8D \
8D A5 C6 05 B0 B4 D5 6B B5 5E 93 64 C7 7B FA D9 \
C8 19 1E D6 E1 FE 7B 7A 93 7C 6D 07 09 5F E5 EA \
91 A7 00 B4 BD FC 17 B4 28 D0 36 92 2A A8 AB 5E \
2C D5 85 84 6F B8 1F C6 93 B8 D5 9B F8 5C 74 BC \
70 0C D2 BC 3E 6A AB 43 7D 93 D8 A3 0F 1C F6 92 \
EF EF 43 60 20 28 E0 CE 57 42 EB 3F 4F 4D 5B 02 \
91 58 DD 68 96 AC B5 E3 A7 F6 84 D9 AA 89 14 E7 \
09 74 B2 23 A6 FE C3 8D 76 C7 47 3E 86 E4 B9 B3 \
2C 62 1E 20 15 C5 5E 94 7D D0 16 C6 75 C8 23 68 \
CE 26 FB 45 6A 5B 65 88 1A F5 13 BF DC 88 68 7C \
63 81 67 6A BB D2 D9 10 4E D2 3A 9E 89 31 02 46 \
B0 26 CE DD 57 59 5B 1A B6 FE 88 A7 84 BE 0C 06";

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf>
    fn test_shake128_0_bits() -> Result<()> {
        let mut hasher = Shake128::new();
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_0_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ShakeTruncation.pdf>
    fn test_shake128_0_bits_in_4094_out() -> Result<()> {
        let mut hasher = Shake128::new();
        let mut result = BitVec::<u8, Lsb0>::with_capacity(4094);
        hasher.finalize()?;
        hasher.get_bits(&mut result, 4094)?;
        assert_eq!(4094, result.len());
        let res = b2h(&result, true, true)?;
        assert_eq!(SHAKE128_0_BITS_4094, res);
        Ok(())
    }

    #[test]
    fn test_shake128_0_bits_in_2048_out_twice() -> Result<()> {
        // Check the first 2048 bits match the 4096 output.
        let mut hasher = Shake128::new();
        let mut result = BitVec::<u8, Lsb0>::with_capacity(4096);
        hasher.finalize()?;
        hasher.get_bits(&mut result, 2048)?;
        assert_eq!(2048, result.len());
        let res = b2h(&result, true, true)?;
        assert_eq!(SHAKE128_0_BITS_2048, res);
        hasher.get_bits(&mut result, 2048)?;
        assert_eq!(4096, result.len());
        let res = b2h(&result, true, true)?;
        assert_eq!(SHAKE128_0_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ShakeTruncation.pdf>
    fn test_shake128_0_bits_in_4088_out() -> Result<()> {
        let mut hasher = Shake128::new();
        let mut result = BitVec::<u8, Lsb0>::with_capacity(4088);
        hasher.finalize()?;
        hasher.get_bits(&mut result, 4088)?;
        assert_eq!(4088, result.len());
        let res = b2h(&result, true, true)?;
        assert_eq!(SHAKE128_0_BITS_4088, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg5.pdf>
    fn test_shake128_5_bits() -> Result<()> {
        let mut hasher = Shake128::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1]);
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_5_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg30.pdf>
    fn test_shake128_30_bits() -> Result<()> {
        let mut hasher = Shake128::new();
        hasher.update_bits(bits![u8, Lsb0; 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0]);
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_30_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg1600.pdf>
    fn test_shake128_1600_bits() -> Result<()> {
        // Create 1600-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1600);
        assert_eq!(1600, bit_vec.len());
        let mut hasher = Shake128::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_1600_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg1605.pdf>
    fn test_shake128_1605_bits() -> Result<()> {
        // Create 1605-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1605);
        assert_eq!(1605, bit_vec.len());
        let mut hasher = Shake128::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_1605_BITS, res);
        Ok(())
    }

    #[test]
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg1630.pdf>
    fn test_shake128_1630_bits() -> Result<()> {
        // Create 1630-bit test vector
        let bit_vec = create_test_vector(Mode::Sha3_1630);
        assert_eq!(1630, bit_vec.len());
        let mut hasher = Shake128::new();
        hasher.update_bits(bit_vec.as_bitslice());
        let mut result = [0u8; NUM_BYTES];
        hasher.finalize()?;
        hasher.get_bytes(&mut result, NUM_BYTES)?;
        let res = b2h(&BitVec::from_slice(&result), true, true)?;
        assert_eq!(SHAKE128_1630_BITS, res);
        Ok(())
    }
}
