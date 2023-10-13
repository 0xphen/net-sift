// IPv4 Header Structure:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
use super::errors::ParserError;

use std::array::TryFromSliceError;
use std::convert::TryFrom;

const BYTE: u8 = 8;

const VERSION_OFFSET: usize = 0;
const VERSION_LENGTH: usize = 1;

const IHL_OFFSET: usize = 1;
const IHL_LENGTH: usize = 1;
const MIN_IHL_VALUE: u8 = 5;
const MAX_IHL_VALUE: u8 = 15;

const DSCP_OFFSET: usize = 2;
const DSCP_LENGTH: usize = 1;

const ECN_OFFSET: usize = 3;
const ECN_LENGTH: usize = 1;

const TOTAL_LENGTH_OFFSET: usize = 4;
const TOTAL_LENGTH_LENGTH: usize = 2;

const IDENTIFICATION_OFFSET: usize = 6;
const IDENTIFICATION_LENGTH: usize = 2;

const FLAGS_OFFSET: usize = 8;
const FLAGS_LENGTH: usize = 1;

const FRAGMENT_OFFSET: usize = 9;
const FRAGMENT_LENGTH: usize = 2;

const TTL_OFFSET: usize = 11;
const TTL_LENGTH: usize = 1;

const PROTOCOL_OFFSET: usize = 12;
const PROTOCOL_LENGTH: usize = 1;

const HEADER_CHECKSUM_OFFSET: usize = 13;
const HEADER_CHECKSUM_LENGTH: usize = 2;

const SRC_ADDRESS_OFFSET: usize = 14;
const SRC_ADDRESS_LENGTH: usize = 4;

const DEST_ADDRESS_OFFSET: usize = 18;
const DEST_ADDRESS_LENGTH: usize = 4;

#[derive(Debug)]
pub struct IPV4 {
    /// A single-byte field indicating the version of the IP protocol.
    /// For IPv4, this is typically set to 4.
    pub version: [u8; 1],

    /// A single-byte field indicating the header length in 32-bit words.
    /// This field determines the start of the optional "options" field and the data/payload.
    pub internet_header_length: [u8; 1],

    /// A single-byte field representing the Differentiated Services Code Point,
    /// which is used for quality of service (QoS) configuration.
    pub dscp: [u8; 1],

    /// A single-byte field for the Explicit Congestion Notification,
    /// indicating the network congestion status.
    pub ecn: [u8; 1],

    /// A two-byte field representing the total length of the IP packet,
    /// including the header and data.
    pub total_length: [u8; 2],

    /// A two-byte field for the identification value, used for
    /// uniquely identifying fragments of an original IP datagram.
    pub identification: [u8; 2],

    /// A single-byte field containing flags related to IP fragmentation,
    /// such as "Don't Fragment" and "More Fragments".
    pub flags: [u8; 1],

    /// A two-byte field indicating where in the original IP datagram
    /// this fragment belongs.
    pub fragment_offset: [u8; 2],

    /// A single-byte field denoting the maximum number of hops
    /// (routers) the packet can traverse before being discarded.
    pub time_to_live: [u8; 1],

    /// A single-byte field indicating the transport layer protocol
    /// used by the packet's data (e.g., TCP, UDP).
    pub protocol: [u8; 1],

    /// A two-byte field for error-checking the header's integrity.
    pub header_checksum: [u8; 2],

    /// A four-byte field representing the source IP address.
    pub source_address: [u8; 4],

    /// A four-byte field representing the destination IP address.
    pub destination_address: [u8; 4],

    /// An optional field containing any additional IP header options,
    /// represented as a vector of bytes. This field is variable in length
    /// and may be absent.
    pub options: Option<Vec<u8>>,

    /// A vector containing the payload or data portion of the IP packet.
    pub payload: Vec<u8>,
}

impl IPV4 {
    pub fn new(packets: Vec<u8>) -> Result<Self, ParserError> {
        let version: [u8; 1] =
            Self::extract_typed_field(&packets, VERSION_OFFSET, VERSION_LENGTH, "Version")?;

        let internet_header_length: [u8; 1] =
            Self::extract_typed_field(&packets, IHL_OFFSET, IHL_LENGTH, "Internet Header Length")?;

        let ihl_value = internet_header_length[0];

        if ihl_value < 5 || ihl_value > 15 {
            return Err(ParserError::InvalidIHLValue(
                ihl_value as u32,
                MIN_IHL_VALUE,
                MAX_IHL_VALUE,
            ));
        }

        let dscp: [u8; 1] = Self::extract_typed_field(&packets, DSCP_OFFSET, DSCP_LENGTH, "DSCP")?;

        let ecn: [u8; 1] = Self::extract_typed_field(&packets, ECN_OFFSET, ECN_LENGTH, "ECN")?;

        let total_length: [u8; 2] = Self::extract_typed_field(
            &packets,
            TOTAL_LENGTH_OFFSET,
            TOTAL_LENGTH_LENGTH,
            "Total Length",
        )?;

        let identification: [u8; 2] = Self::extract_typed_field(
            &packets,
            IDENTIFICATION_OFFSET,
            IDENTIFICATION_LENGTH,
            "Identification",
        )?;

        let flags: [u8; 1] =
            Self::extract_typed_field(&packets, FLAGS_OFFSET, FLAGS_LENGTH, "Flags")?;

        let fragment_offset: [u8; 2] = Self::extract_typed_field(
            &packets,
            FRAGMENT_OFFSET,
            FRAGMENT_LENGTH,
            "Fragments Offset",
        )?;

        let time_to_live: [u8; 1] =
            Self::extract_typed_field(&packets, TTL_OFFSET, TTL_LENGTH, "TTL")?;

        let protocol: [u8; 1] =
            Self::extract_typed_field(&packets, PROTOCOL_OFFSET, PROTOCOL_LENGTH, "Protocol")?;

        let header_checksum: [u8; 2] = Self::extract_typed_field(
            &packets,
            HEADER_CHECKSUM_OFFSET,
            HEADER_CHECKSUM_LENGTH,
            "Header Checksum",
        )?;

        let source_address: [u8; 4] = Self::extract_typed_field(
            &packets,
            SRC_ADDRESS_OFFSET,
            SRC_ADDRESS_LENGTH,
            "Source Address",
        )?;

        let destination_address: [u8; 4] = Self::extract_typed_field(
            &packets,
            DEST_ADDRESS_OFFSET,
            DEST_ADDRESS_LENGTH,
            "Destination Address",
        )?;

        let (options_offset, options_size, payload_offset) =
            Self::payload_and_options_offsets(ihl_value as usize);

        let payload: Vec<u8> = Self::extract_bytes_as_vector(
            &packets,
            payload_offset,
            ((packets.len() - 1) - (options_offset + options_size)),
            "Payload",
        )?;

        let options: Option<Vec<u8>> = match options_offset {
            0 => None,
            _ => {
                let options: Vec<u8> = Self::extract_bytes_as_vector(
                    &packets,
                    options_offset,
                    options_size,
                    "Options",
                )?;
                Some(options)
            }
        };

        Ok(IPV4 {
            version,
            internet_header_length,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            time_to_live,
            protocol,
            header_checksum,
            source_address,
            destination_address,
            options,
            payload,
        })
    }

    /// Extracts a specific field from a given packet based on the provided offset and length.
    ///
    /// This function is designed to facilitate the extraction of IPV4 fields from a packet.
    /// The type of the extracted field is determined by the type parameter `T`, which must implement
    /// the `TryFrom<&'a [u8], Error = TryFromSliceError>` trait.
    ///
    /// # Parameters
    /// - `packet`: A slice of the packet data.
    /// - `offset`: The starting position from which the field should be extracted.
    /// - `length`: The number of bytes to extract for this field.
    /// - `field`: A string representation (name) of the field being extracted (used for error reporting).
    ///
    /// # Returns
    /// - `Ok(T)`: The extracted field of type `T`.
    /// - `Err(ParserError::PacketTooShort)`: If the packet is too short to contain the expected field.
    /// - `Err(ParserError::ExtractionError)`: If there's an error during extraction.
    fn extract_typed_field<'a, T>(
        packet: &'a [u8],
        offset: usize,
        length: usize,
        field: &str,
    ) -> Result<T, ParserError>
    where
        T: TryFrom<&'a [u8], Error = TryFromSliceError>,
    {
        if packet.len() < offset + length {
            return Err(ParserError::PacketTooShort(
                packet.len(),
                length,
                field.to_string(),
            ));
        }

        T::try_from(&packet[offset..offset + length]).map_err(|e| ParserError::ExtractionError {
            source: e,
            string: field.to_string(),
        })
    }

    /// Extracts a field from the given packet as a byte vector (`Vec<u8>`).
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice representing the packet from which the field needs to be extracted.
    /// * `offset` - The starting position within the packet from which extraction should begin.
    /// * `length` - The number of bytes to extract from the packet.
    /// * `field`  - A description or name for the field being extracted. This is used for error messages.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, ParserError>` - A `Result` which, on success, contains the extracted bytes as a `Vec<u8>`.
    ///   On failure, it contains a `ParserError` indicating the reason for the failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The given offset and length would result in out-of-bounds access on the packet.
    fn extract_bytes_as_vector(
        packet: &[u8],
        offset: usize,
        length: usize,
        field: &str,
    ) -> Result<Vec<u8>, ParserError> {
        if packet.len() < offset + length {
            return Err(ParserError::PacketTooShort(
                packet.len(),
                length,
                field.to_string(),
            ));
        }

        Ok(packet[offset..offset + length].to_vec())
    }

    /// Calculates the offsets and size for the options and payload fields in an IPv4 packet based on the provided Internet Header Length (IHL).
    ///
    /// The IPv4 header has a variable length due to the optional "options" field. This function helps in determining the start and end points
    /// of both the options and payload sections of the packet based on the provided IHL value.
    ///
    /// # Arguments
    ///
    /// * `ihl` - The Internet Header Length field value from the IPv4 header. This represents the length of the header in 32-bit words.
    ///
    /// # Returns
    ///
    /// * A tuple consisting of three `usize` values:
    ///   - `options_offset`: The starting offset (position) of the options field within the packet.
    ///   - `options_size`: The size (in bytes) of the options field.
    ///   - `payload_offset`: The starting offset (position) of the payload/data section of the packet.
    ///
    /// # Notes
    ///
    /// If the IHL value is 5 or less (meaning there are no options in the header), the function will return `(0, 0, DEST_ADDRESS_OFFSET + DEST_ADDRESS_LENGTH)`.
    /// This indicates that there is no options section and the payload starts immediately after the fixed header section.
    ///
    /// The calculation for the options' size is based on the understanding that each IHL unit corresponds to 4 bytes and the base header size without options is 20 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// let ihl_value = 6; // Example IHL value indicating presence of options.
    /// let (options_start, options_size, payload_start) = payload_and_options_offsets(ihl_value);
    /// ```
    ///
    fn payload_and_options_offsets(ihl: usize) -> (usize, usize, usize) {
        if ihl > 5 {
            let options_size = (ihl * 4) - 20; // 4 bytes per IHL unit minus base header size
            let options_offset = DEST_ADDRESS_OFFSET + DEST_ADDRESS_LENGTH;
            let payload_offset = options_offset + options_size;
            return (options_offset, options_size, payload_offset);
        }

        (0, 0, DEST_ADDRESS_OFFSET + DEST_ADDRESS_LENGTH)
    }
}
