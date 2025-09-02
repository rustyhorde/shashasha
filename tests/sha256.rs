use anyhow::Result;
use shashasha::{BitVec, Hasher, HasherBits, Lsb0, SHA3_256_BYTES, Sha3_256, b2h, bits};

#[test]
fn sha256_with_update() -> Result<()> {
    let mut hasher = Sha3_256::new();
    let mut result = [0u8; SHA3_256_BYTES];
    hasher.update(b"Hello, world!")?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_256_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722",
        res
    );
    Ok(())
}

#[test]
fn sha256_with_update_bits() -> Result<()> {
    let mut hasher = Sha3_256::default();
    let mut result = [0u8; SHA3_256_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1])?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_256_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "ca6a4b6b2ebb3d64d53b70298ad758f687621e9011871f1265f5b143aa6415fe",
        res
    );
    Ok(())
}
