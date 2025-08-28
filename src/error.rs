// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use thiserror::Error;

/// Sha3 Error
#[derive(Copy, Clone, Debug, Error)]
pub enum Sha3Error {
    /// Thrown if the round count is not allowed for the given `Lane` size
    #[error("Invalid round count")]
    InvalidRoundCount(usize),
    /// Thrown if the truncate function fails for the given round constant
    #[error("Truncate failed")]
    TruncateFailed(u64),
    /// Thrown if the number of bits does not match the output length given to the squeezed function
    #[error("Output length does not match number of bits")]
    OutputLengthMismatch(usize, usize),
}
