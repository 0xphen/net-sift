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

    #[error("Packet too short got `{0}`, expected at least `{1}`")]
    PacketTooShort(usize, usize),

    #[error("Frame too short got `{0}`, expected at least `{1}`")]
    FrameTooShort(usize, usize),

    #[error("Segment too short got `{0}`, expected at least `{1}`")]
    SegmentTooShort(usize, usize),

    #[error("Invalid IHL value got `{0}`, expected >=`{1}` or <= `{2}`")]
    InvalidIHLValue(u32, u8, u8),

    #[error("Invalid EtherType")]
    InvalidEtherType,
}
