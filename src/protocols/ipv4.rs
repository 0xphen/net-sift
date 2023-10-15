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

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::net::Ipv4Addr;

const MIN_IHL_VALUE: u8 = 5;
const MAX_IHL_VALUE: u8 = 15;

const DEST_ADDRESS_OFFSET: usize = 18;
const DEST_ADDRESS_LENGTH: usize = 4;

const MIN_PACKET_SIZE: usize = 20;

#[derive(Debug, PartialEq)]
pub enum IPType {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl From<u8> for IPType {
    fn from(byte: u8) -> IPType {
        match byte {
            1 => IPType::ICMP,
            6 => IPType::TCP,
            17 => IPType::UDP,
            _ => IPType::Other(byte),
        }
    }
}

#[derive(Debug)]
pub struct IPV4 {
    /// A single-byte field indicating the version of the IP protocol.
    /// For IPv4, this is typically set to 4.
    pub version: u8,

    pub type_of_service: u8,

    /// A single-byte field indicating the header length in 32-bit words.
    /// This field determines the start of the optional "options" field and the data/payload.
    pub internet_header_length: u8,

    /// A two-byte field representing the total length of the IP packet,
    /// including the header and data.
    pub total_length: u16,

    /// A two-byte field for the identification value, used for
    /// uniquely identifying fragments of an original IP datagram.
    pub identification: u16,

    /// A single-byte field containing flags related to IP fragmentation,
    /// such as "Don't Fragment" and "More Fragments".
    pub flags: u8,

    /// A two-byte field indicating where in the original IP datagram
    /// this fragment belongs.
    pub fragment_offset: u16,

    /// A single-byte field denoting the maximum number of hops
    /// (routers) the packet can traverse before being discarded.
    pub time_to_live: u8,

    /// A single-byte field indicating the transport layer protocol
    /// used by the packet's data (e.g., TCP, UDP).
    pub protocol: IPType,

    /// A two-byte field for error-checking the header's integrity.
    pub header_checksum: u16,

    /// A four-byte field representing the source IP address.
    pub source_address: Ipv4Addr,

    /// A four-byte field representing the destination IP address.
    pub destination_address: Ipv4Addr,

    /// An optional field containing any additional IP header options,
    /// represented as a vector of bytes. This field is variable in length
    /// and may be absent.
    pub options: Option<Vec<u8>>,

    /// A vector containing the payload or data portion of the IP packet.
    pub payload: Vec<u8>,
}

impl IPV4 {
    /// Constructs a new instance of `IPV4` by parsing raw packet data.
    ///
    /// This function expects `packets` to contain the raw bytes of an IPv4 packet and
    /// tries to extract various fields from these bytes.
    ///
    /// # Arguments
    /// - `packets`: A byte slice representing the raw data of an IPv4 packet.
    ///
    /// # Returns
    /// - `Result<IPV4, ParserError>`: An `IPV4` instance if the parsing was successful,
    /// or an error indicating the reason for failure.
    pub fn new(packets: &[u8]) -> Result<Self, ParserError> {
        // Ensure packet is of minimum expected length.
        if packets.len() < MIN_PACKET_SIZE {
            return Err(ParserError::PacketTooShort(packets.len(), MIN_PACKET_SIZE));
        }
        let mut cursor = Cursor::new(packets);

        let version_ihl = Self::read_u8(&mut cursor, "Version & IHL")?;

        // Right shift the byte `version_ihl` 4 times to get the version
        // which is in the MSB.
        let version = version_ihl >> 4;
        let internet_header_length = version_ihl & 15;

        // Ensure the IHL is between 5 and 15.
        if internet_header_length < 5 || internet_header_length > 15 {
            return Err(ParserError::InvalidIHLValue(
                internet_header_length as u32,
                MIN_IHL_VALUE,
                MAX_IHL_VALUE,
            ));
        }

        let type_of_service = Self::read_u8(&mut cursor, "ToS")?;
        let total_length = Self::read_u16(&mut cursor, "Total Length")?;

        let identification = Self::read_u16(&mut cursor, "Identification")?;

        let flags_fragment = Self::read_u16(&mut cursor, "Flags & Fragment")?;

        // Right shift the byte `flags_fragment` 13 times to get the flags
        // which is in the MSB.
        let flags = (flags_fragment >> 13) as u8;
        let fragment_offset = flags_fragment & 8191;

        let time_to_live = Self::read_u8(&mut cursor, "TTL")?;
        let protocol = IPType::from(Self::read_u8(&mut cursor, "Protocol")?);
        let header_checksum = Self::read_u16(&mut cursor, "Header Checksum")?;

        let [a, b, c, d] = u32::to_be_bytes(Self::read_u32(&mut cursor, "Source Address")?);
        let source_address = Ipv4Addr::new(a, b, c, d);

        let [a, b, c, d] = u32::to_be_bytes(Self::read_u32(&mut cursor, "Source Address")?);
        let destination_address = Ipv4Addr::new(a, b, c, d);

        // Calculate offsets and sizes for options and payload data.
        let (options_offset, options_size, _payload_offset) =
            Self::payload_and_options_offsets(internet_header_length as usize);

        let mut options: Option<Vec<u8>> = Default::default();
        let payload: Vec<u8>;

        if options_offset != 0 {
            cursor
                .seek(SeekFrom::Start(options_offset as u64))
                .map_err(|e| ParserError::CursorError {
                    string: "Options".to_string(),
                    source: e,
                })?;

            options = Some(Self::read_arbitrary_length(
                &mut cursor,
                options_size,
                "Options",
            )?);
        }

        let payload_size = total_length - (internet_header_length as u16 * 4);

        payload = Self::read_arbitrary_length(&mut cursor, payload_size as usize, "Payload")?;

        Ok(IPV4 {
            version,
            internet_header_length,
            type_of_service,
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

    /// Reads a single byte (`u8`) from the cursor's current position.
    ///
    /// # Arguments
    /// - `cursor`: The cursor pointing to the data.
    /// - `field`: The name of the field being read, for error context.
    ///
    /// # Returns
    /// - `Result<u8, ParserError>`: The read byte or an error.
    fn read_u8(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u8, ParserError> {
        let mut buffer: [u8; 1] = Default::default();

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                source: e,
                string: field.to_string(),
            })?;

        Ok(u8::from_be_bytes(buffer))
    }

    /// Reads two bytes and converts them into a `u16` integer.
    ///
    /// # Arguments
    /// - `cursor`: The cursor pointing to the data.
    /// - `field`: The name of the field being read, for error context.
    ///
    /// # Returns
    /// - `Result<u16, ParserError>`: The read `u16` integer or an error.
    fn read_u16(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u16, ParserError> {
        let mut buffer: [u8; 2] = Default::default();

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                source: e,
                string: field.to_string(),
            })?;

        Ok(u16::from_be_bytes(buffer))
    }

    /// Reads four bytes and converts them into a `u32` integer.
    ///
    /// # Arguments
    /// - `cursor`: The cursor pointing to the data.
    /// - `field`: The name of the field being read, for error context.
    ///
    /// # Returns
    /// - `Result<u32, ParserError>`: The read `u32` integer or an error.
    fn read_u32(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u32, ParserError> {
        let mut buffer: [u8; 4] = Default::default();

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                source: e,
                string: field.to_string(),
            })?;

        Ok(u32::from_be_bytes(buffer))
    }

    /// Reads a specified number of bytes from the cursor's current position.
    ///
    /// # Arguments
    /// - `cursor`: The cursor pointing to the data.
    /// - `length`: The number of bytes to read.
    /// - `field`: The name of the field being read, for error context.
    ///
    /// # Returns
    /// - `Result<Vec<u8>, ParserError>`: The read bytes as a `Vec<u8>` or an error.
    fn read_arbitrary_length(
        cursor: &mut Cursor<&[u8]>,
        length: usize,
        field: &str,
    ) -> Result<Vec<u8>, ParserError> {
        let mut buffer = vec![0; length];

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                source: e,
                string: field.to_string(),
            })?;

        Ok(buffer)
    }
    /// Calculate offsets and sizes for the optional "options" field and the "payload" data
    /// based on the Internet Header Length (IHL) field in the IPv4 header.
    ///
    /// The IHL field indicates the length of the header in 32-bit words. To determine the
    /// location and size of the "options" field and the "payload" data, we perform the
    /// following calculations:
    ///
    /// - If the IHL is greater than the minimum expected value of 5 (indicating the presence
    ///   of additional options), we calculate the size of the "options" field as follows:
    ///   - Multiply the IHL value by 4 (each IHL unit represents 32 bits or 4 bytes).
    ///   - Subtract the size of the base header (20 bytes) to get the options size.
    ///   - Set the options offset to the end of the base header (destination address + 4 bytes).
    ///   - Calculate the payload offset as the options offset plus the options size.
    ///
    /// - If the IHL is 5 (indicating no additional options), there are no "options" in the header.
    ///   - Set both the options offset and options size to 0.
    ///   - Calculate the payload offset as the end of the base header (destination address + 4 bytes).
    ///
    /// # Arguments
    /// - `ihl`: The Internet Header Length (IHL) field from the IPv4 header.
    ///
    /// # Returns
    /// - A tuple containing:
    ///   1. Options offset: The offset where the "options" field starts in the header.
    ///   2. Options size: The size (in bytes) of the "options" field.
    ///   3. Payload offset: The offset where the "payload" data starts in the header.
    fn payload_and_options_offsets(ihl: usize) -> (usize, usize, usize) {
        if ihl > MIN_IHL_VALUE as usize {
            let options_size = (ihl * 4) - MIN_PACKET_SIZE; // 4 bytes per IHL unit minus base header size
            let options_offset = DEST_ADDRESS_OFFSET + DEST_ADDRESS_LENGTH;
            let payload_offset = options_offset + options_size;
            return (options_offset, options_size, payload_offset);
        }

        // If IHL is 5 (no options), there are no "options" in the header
        // Set both options offset and options size to 0
        (0, 0, DEST_ADDRESS_OFFSET + DEST_ADDRESS_LENGTH)
    }
}
