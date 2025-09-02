use anyhow::Result;
use shashasha::{BitVec, Hasher, HasherBits, Lsb0, SHA3_512_BYTES, Sha3_512, b2h, bits};

#[test]
fn sha512_with_update() -> Result<()> {
    let mut hasher = Sha3_512::new();
    let mut result = [0u8; SHA3_512_BYTES];
    hasher.update(b"Hello, world!")?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_512_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af",
        res
    );
    Ok(())
}

#[test]
fn sha512_with_update_bits() -> Result<()> {
    let mut hasher = Sha3_512::default();
    let mut result = [0u8; SHA3_512_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1])?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_512_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "1483be482b6712e47c08127ccc08160253d02357c7569523b59d1bebfb05e13c0958a4cdbd1869fc4ad8e6da33557325915157e2c72da41a9d7139670603af57",
        res
    );
    Ok(())
}
