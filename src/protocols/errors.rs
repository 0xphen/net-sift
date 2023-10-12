use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthernetFrameError {
    #[error("Failed to extract MAC address: {source}")]
    MacAddressExtractionError {
        #[source]
        source: std::array::TryFromSliceError,
    },

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
}
