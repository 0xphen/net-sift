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

use super::{
    definitions::{DeepParser, IPType, LayeredData},
    errors::ParserError,
    utils::{parse_ip_next_protocol_layer, read_arbitrary_length, read_u16, read_u32, read_u8},
};

use std::io::{Cursor, Seek, SeekFrom};
use std::net::Ipv4Addr;

const MIN_IHL_VALUE: u8 = 5;
const MAX_IHL_VALUE: u8 = 15;

const DEST_ADDRESS_OFFSET: usize = 16;
const DEST_ADDRESS_LENGTH: usize = 4;

const MIN_PACKET_SIZE: usize = 20;

#[derive(Debug, PartialEq)]
pub struct Ipv4PacketHeader {
    /// A single-byte field indicating the version of the IP protocol.
    /// For Ipv4, this is typically set to 4.
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
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet {
    pub header: Ipv4PacketHeader,
    /// A vector containing the payload or data portion of the IP packet.
    pub data: Box<LayeredData>,
}

impl Ipv4Packet {
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
    pub fn from_bytes(packets: &[u8]) -> Result<Self, ParserError> {
        // Ensure packet is of minimum expected length.
        if packets.len() < MIN_PACKET_SIZE {
            return Err(ParserError::InvalidLength);
        }
        let mut cursor = Cursor::new(packets);

        let version_ihl = read_u8(&mut cursor, "Version & IHL")?;

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

        let type_of_service = read_u8(&mut cursor, "ToS")?;
        let total_length = read_u16(&mut cursor, "Total Length")?;
        let identification = read_u16(&mut cursor, "Identification")?;
        let flags_fragment = read_u16(&mut cursor, "Flags & Fragment")?;

        // Right shift the byte `flags_fragment` 13 times to get the flags
        // which is in the MSB.
        let flags = (flags_fragment >> 13) as u8;
        let fragment_offset = flags_fragment & 8191;

        let time_to_live = read_u8(&mut cursor, "TTL")?;
        let protocol = IPType::from(read_u8(&mut cursor, "Protocol")?);
        let header_checksum = read_u16(&mut cursor, "Header Checksum")?;

        let [a, b, c, d] = u32::to_be_bytes(read_u32(&mut cursor, "Source Address")?);
        let source_address = Ipv4Addr::new(a, b, c, d);

        let [a, b, c, d] = u32::to_be_bytes(read_u32(&mut cursor, "Source Address")?);
        let destination_address = Ipv4Addr::new(a, b, c, d);

        let (options, data) = Self::parse_options_and_payload(
            &mut cursor,
            internet_header_length as u16,
            total_length,
        )?;

        Ok(Ipv4Packet {
            header: Ipv4PacketHeader {
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
            },
            data: Box::new(LayeredData::Payload(data)),
        })
    }

    /// Parses the options and payload from a network packet.
    ///
    /// Given the `internet_header_length` and `total_length` from the packet's header,
    /// this function extracts optional information (if present) and the main payload.
    ///
    /// # Parameters
    /// * `cursor`: A mutable reference to a `Cursor` positioned at the start of the packet data.
    /// * `internet_header_length`: The header length value from the packet, indicating where option data (if any) starts.
    /// * `total_length`: The total packet length value, used to calculate the payload's size.
    ///
    /// # Returns
    /// * On success, returns a tuple containing an `Option<Vec<u8>>` for options (None if no options are present)
    ///   and a `Vec<u8>` for the payload.
    /// * On failure, returns a `ParserError` indicating the reason for the failure.
    ///
    /// # Errors
    /// * Returns `ParserError::CursorError` if the function fails to seek the cursor to the correct position.
    /// * May also return other errors encapsulated by `ParserError` if reading from the cursor fails.
    fn parse_options_and_payload(
        cursor: &mut Cursor<&[u8]>,
        internet_header_length: u16,
        total_length: u16,
    ) -> Result<(Option<Vec<u8>>, Vec<u8>), ParserError> {
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

            options = Some(read_arbitrary_length(cursor, options_size, "Options")?);
        }

        let payload_size = total_length - (internet_header_length as u16 * 4);

        payload = read_arbitrary_length(cursor, payload_size as usize, "IPV4_Data")?;

        Ok((options, payload))
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

impl DeepParser for Ipv4Packet {
    /// Parses the payload based on the protocol specified in the IPv4 packet header.
    ///
    /// This method inspects the current protocol layer, extracts its payload, and attempts
    /// to parse that payload into a structured format suitable for further analysis or
    /// processing. This process advances the analysis to the next protocol layer, if applicable.
    ///
    /// # Side Effects
    /// * Alters the `data` field of the instance, replacing the original payload with the
    ///   parsed data corresponding to the next protocol layer. The initial payload is not
    ///   preserved after this transformation.
    ///
    /// # Behavior
    /// * Identifies the protocol used within the packet's payload (e.g., TCP, UDP, ICMP).
    /// * Initiates the appropriate parsing routine based on the identified protocol.
    /// * Handles unsupported or unrecognized protocols by returning an error.
    ///
    /// # Returns
    /// * `Ok(LayeredData)` - If the payload is successfully parsed, encapsulating the results
    ///   within a `LayeredData` enum for further manipulation or inspection.
    /// * `Err(ParserError)` - If the payload's protocol is unrecognized or if any issues arise
    ///   during the parsing phase, detailed within the `ParserError` enum.
    ///
    /// # Errors
    /// The method may fail if:
    /// * The protocol specified in the packet's header is unsupported or unknown.
    /// * There are issues encountered during the parsing process, such as malformed data or
    ///   unexpected input.
    fn parse_next_layer(mut self) -> Result<LayeredData, ParserError> {
        let layered_data: LayeredData =
            parse_ip_next_protocol_layer(&*self.data, &self.header.protocol)?;

        *self.data = layered_data;
        Ok(LayeredData::Ipv4Data(self))
    }
}
