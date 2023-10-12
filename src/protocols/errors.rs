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
