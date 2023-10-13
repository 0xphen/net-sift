use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthernetFrameError {
    #[error("Failed to extract MAC address: {source}")]
    MacAddressExtractionError {
        #[source]
        source: std::array::TryFromSliceError,
    },

    #[error("Frame too short got `{0}`, expected `{1}` `{2}`")]
    FrameTooShort(usize, usize, String),

    #[error("Failed to extract Q-Tag: {source}")]
    QTagExtractionError {
        #[source]
        source: std::array::TryFromSliceError,
    },

    #[error("Failed to extract ether type: {source}")]
    EtherTypeExtractionError {
        #[source]
        source: std::array::TryFromSliceError,
    },

    #[error("Failed to extract FCS: {source}")]
    FCSExtractionError {
        #[source]
        source: std::array::TryFromSliceError,
    },

    #[error("Invalid EtherType")]
    InvalidEtherType,

    #[error("Invalid ethernet frame. Frame has `{0}` bytes")]
    InvalidEthernetFrame(usize),
}

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Extraction of `{string}` failed")]
    ExtractionError {
        string: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to seek in cursor for `{string}`")]
    CursorError {
        string: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Packet too short got `{0}`, expected at least `{1}`")]
    PacketTooShort(usize, usize),

    #[error("Invalid IHL value got `{0}`, expected >=`{1}` or <= `{2}`")]
    InvalidIHLValue(u32, u8, u8),
}
