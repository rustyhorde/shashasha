use anyhow::Result;
use shashasha::{BitVec, Lsb0, SHA3_512_BYTES, Shake128, XofHasher, XofHasherBits, b2h, bits};

#[test]
fn shake128_with_update() -> Result<()> {
    let mut hasher = Shake128::new();
    let mut result = [0u8; SHA3_512_BYTES];
    hasher.update(b"Hello, world!")?;
    hasher.finalize()?;
    hasher.get_bytes(&mut result, SHA3_512_BYTES)?;
    assert_eq!(result.len(), SHA3_512_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "b5ffd113fa127f4d9c7e483cb52264ed413554ef899c0cf7c1d736ddb93313a6e76a35e24c33882d9e7c3ec4a9e0ff5fc55384da25ede64c4b721040fd873935",
        res
    );
    Ok(())
}

#[test]
fn shake128_with_update_bits() -> Result<()> {
    let mut hasher = Shake128::new();
    let mut result = [0u8; SHA3_512_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1])?;
    hasher.finalize()?;
    hasher.get_bytes(&mut result, SHA3_512_BYTES)?;
    assert_eq!(result.len(), SHA3_512_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "ea5a03be08c441aaed7fa1557322c04b808733391eea4853497b8eb86ce8c738e79c7f509da6c34f323f26319b8c1cc16edf3a0dff67babefff88cfab799d17f",
        res
    );
    Ok(())
}

#[test]
fn shake128_with_update_iter_explicit_finalize() -> Result<()> {
    let mut hasher = Shake128::new();
    hasher.update(b"Hello, world!")?;
    hasher.finalize()?;
    let result = hasher.by_ref().take(4).collect::<Vec<u8>>();
    assert_eq!(4, result.len());
    let res = b2h(&BitVec::from_slice(&result), false, false)?;
    assert_eq!("b5ffd113", res);
    let next = hasher.next();
    assert_eq!(Some(0xFA), next);
    let next = hasher.next();
    assert_eq!(Some(0x12), next);
    Ok(())
}

#[test]
fn shake128_with_update_iter_implicit_finalize() -> Result<()> {
    let mut hasher = Shake128::new();
    hasher.update(b"Hello, world!")?;
    let result = hasher.by_ref().take(4).collect::<Vec<u8>>();
    assert_eq!(4, result.len());
    let res = b2h(&BitVec::from_slice(&result), false, false)?;
    assert_eq!("b5ffd113", res);
    let next = hasher.next();
    assert_eq!(Some(0xFA), next);
    let next = hasher.next();
    assert_eq!(Some(0x12), next);
    Ok(())
}
