use thiserror::Error;

use std::fmt;

#[derive(Debug)]
pub enum ErrorSource {
    Io(std::io::Error),
    TryFromSlice(std::array::TryFromSliceError),
}

// Implementing the std::fmt::Display trait to enable printing the error.
impl fmt::Display for ErrorSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorSource::Io(e) => write!(f, "IO error: {}", e),
            ErrorSource::TryFromSlice(e) => write!(f, "Try from slice error: {}", e),
        }
    }
}

impl std::error::Error for ErrorSource {}

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Extraction of `{string}` failed")]
    ExtractionError {
        string: String,
        #[source]
        source: ErrorSource,
    },

    #[error("Failed to seek in cursor for `{string}`")]
    CursorError {
        string: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid IHL value got `{0}`, expected >=`{1}` or <= `{2}`")]
    InvalidIHLValue(u32, u8, u8),

    #[error("Invalid EtherType")]
    InvalidEtherType,

    #[error("Invalid packet/segment length")]
    InvalidLength,

    #[error("Expected payload data")]
    InvalidPayload,

    #[error("Unknown IP type `{0}`")]
    UnknownIPType(u8),

    #[error("Unknown ether type type")]
    UnSupportedEtherType,
}
