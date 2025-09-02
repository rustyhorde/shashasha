use anyhow::Result;
use shashasha::{BitVec, Hasher, HasherBits, Lsb0, SHA3_384_BYTES, Sha3_384, b2h, bits};

#[test]
fn sha384_with_update() -> Result<()> {
    let mut hasher = Sha3_384::new();
    let mut result = [0u8; SHA3_384_BYTES];
    hasher.update(b"Hello, world!")?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_384_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a",
        res
    );
    Ok(())
}

#[test]
fn sha384_with_update_bits() -> Result<()> {
    let mut hasher = Sha3_384::default();
    let mut result = [0u8; SHA3_384_BYTES];
    hasher.update_bits(bits![u8, Lsb0; 1, 0, 1])?;
    hasher.finalize(&mut result)?;
    assert_eq!(result.len(), SHA3_384_BYTES);
    let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
    assert_eq!(
        "68c850e2f7c9278ad9d362224f1fc5dcb3b19770f8a3e0c682cc6772559489f5a6a50acd6618c8f43803f1739976d240",
        res
    );
    Ok(())
}
