/// Errors returned by sntrup761 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Byte slice has the wrong length for conversion.
    #[error("invalid size: expected {expected} bytes, got {actual}")]
    InvalidSize {
        /// Expected size.
        expected: usize,
        /// Provided size.
        actual: usize,
    },
}
