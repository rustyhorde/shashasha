# shashasha - A SHA3 Implementation

<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>

```rust
use anyhow::Result;
use shashasha::{b2h, bits, BitVec, Hasher, HasherBits, Lsb0, Sha3_224, SHA3_224_BYTES, Shake128, Shake256, XofHasher, XofHasherBits};

pub fn main() -> Result<()> {
    // Hash some byte data
    let mut hasher = Sha3_224::new();
    let mut result = [0u8; SHA3_224_BYTES];
    hasher.update(b"Hello, world!");
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_224_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!("6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69", res);

    // ...or hash some bits
    let mut hasher = Sha3_224::new();
    let mut result = [0u8; SHA3_224_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1]);
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_224_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!("d115e9e3c619f6180c234dba721b302ffe0992df07eeea47464923c0", res);

    // ...or generate an arbitrary number of bits
    // bits can be generated for as long as the original hasher isn't dropped
    let mut hasher = Shake128::new();
    let mut result = BitVec::<u8, Lsb0>::with_capacity(32);
    hasher.finalize()?;
    hasher.get_bits(&mut result, 8)?;
    assert_eq!(8, result.len());
    let res = b2h(&result, false, false)?;
    assert_eq!("7f", res);
    hasher.get_bits(&mut result, 16)?;
    assert_eq!(24, result.len());
    let res = b2h(&result, false, false)?;
    assert_eq!("7f9c2b", res);
    hasher.get_bits(&mut result, 3)?;
    assert_eq!(27, result.len());
    let res = b2h(&result, false, false)?;
    assert_eq!("7f9c2b04", res);
    hasher.get_bits(&mut result, 5)?;
    assert_eq!(32, result.len());
    let res = b2h(&result, false, false)?;
    assert_eq!("7f9c2ba4", res);

    // ...or generate an arbitrary number of bytes through an iterator
    let mut hasher = Shake256::new();
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1]);
    hasher.finalize()?;
    let result = hasher.by_ref().take(4).collect::<Vec<u8>>();
    assert_eq!(4, result.len());
    let res = b2h(&BitVec::from_slice(&result), false, false)?;
    assert_eq!("6f18287d", res);
    let next = hasher.next();
    assert_eq!(Some(0x53), next);
    let next = hasher.next();
    assert_eq!(Some(0x75), next);

    Ok(())
}
```
