use anyhow::Result;
use shashasha::{BitVec, Hasher, HasherBits, Lsb0, SHA3_224_BYTES, Sha3_224, b2h, bits};

#[test]
fn sha224_with_update() -> Result<()> {
    let mut hasher = Sha3_224::new();
    let mut result = [0u8; SHA3_224_BYTES];
    hasher.update(b"Hello, world!")?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_224_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69",
        res
    );
    Ok(())
}

#[test]
fn sha224_with_update_bits() -> Result<()> {
    let mut hasher = Sha3_224::default();
    let mut result = [0u8; SHA3_224_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1])?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_224_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "d115e9e3c619f6180c234dba721b302ffe0992df07eeea47464923c0",
        res
    );
    Ok(())
}
