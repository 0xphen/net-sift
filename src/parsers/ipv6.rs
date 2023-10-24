// 0               16              32              48              64
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                       Destination Address                     +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{
    errors::{ErrorSource, ParserError},
    utils::read_u32,
};

use std::io::Cursor;
use std::net::Ipv6Addr;

const SRC_ADDRESS_OFFSET: usize = 8;
const DEST_ADDRESS_OFFSET: usize = 24;
const PAYLOAD_OFFSET: usize = 40;
const MIN_PACKET_SIZE: usize = 40;

#[derive(Debug, PartialEq)]
pub struct Ipv6 {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
    pub payload: Vec<u8>,
}

impl Ipv6 {
    /// Constructs a new `Ipv6` object from a slice of bytes representing
    /// an IPv6 packet.
    /// This function parses the byte slice, extracting essential
    ///  components of the IPv6 header and payload, including the
    /// version, traffic class, flow label, payload length, next header,
    ///  hop limit, source address, destination address, and the
    ///  payload itself. It then constructs an `Ipv6` object
    ///  containing these components.
    ///
    /// # Parameters
    /// - `packets`: A byte slice representing a complete IPv6
    /// packet, including both header and payload.
    ///
    /// # Returns
    /// If the operation is successful, the function returns an
    /// `Ok` wrapping the `Ipv6` object.
    /// If there's an error during parsing, it returns an `Err`
    ///  wrapping a `ParserError` variant indicating the
    /// kind of error that occurred (e.g., the packet is too short,
    ///  data extraction error, etc.).
    ///
    /// # Errors
    /// This function will return an error in the following situations,
    /// but is not limited to just these cases:
    /// - The packet is too short to contain a valid IPv6 header.
    /// - There's an error extracting data for one of the packet's components.
    /// - There's an inconsistency between the stated payload length
    ///  and the actual data available.
    // TODO: Optimise this function. Use of cursor and slice isn't efficient
    pub fn new(packets: &[u8]) -> Result<Self, ParserError> {
        // Ensure packet is of minimum expected length.
        if packets.len() < MIN_PACKET_SIZE {
            return Err(ParserError::PacketTooShort(packets.len(), MIN_PACKET_SIZE));
        }
        let mut cursor = Cursor::new(packets);

        // Parse the first segment of the packet: version, traffic class, and flow label.
        // These are contained in the first 32 bits of the IPv6 header.
        let (version, traffic_class, flow_label) =
            Self::extract_ipv6_version_trafficclass_flowlabel(&mut cursor)?;

        // Parse the next segment of the packet: payload length, next header, and hop limit.
        // These are contained in the subsequent 32 bits of the IPv6 header.
        let (payload_length, next_header, hop_limit) =
            Self::extract_ipv6_length_header_hoplimit(&mut cursor)?;

        // Extract the source and destination addresses.
        // These are each 128 bits (or 16 bytes) and are located after the initial 64-bit header.
        let src_address_bytes = Self::extract_ipv6_address(packets, SRC_ADDRESS_OFFSET)?;
        let dest_address_bytes = Self::extract_ipv6_address(packets, DEST_ADDRESS_OFFSET)?;

        // Extract the payload. It's the segment of the packet that follows the IPv6 header
        // and addresses, which contains the actual transmitted data.
        let payload = (&packets[PAYLOAD_OFFSET..(packets.len())]).to_vec();

        Ok(Ipv6 {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address: Ipv6Addr::from(src_address_bytes),
            destination_address: Ipv6Addr::from(dest_address_bytes),
            payload,
        })
    }

    /// Parses the first 32 bits of an IPv6 header from the given cursor, extracting the version, traffic class, and flow label.
    ///
    /// The function reads a 32-bit segment from the cursor's current position and then extracts:
    /// 1. Version (4 bits): Identifies the IP version, which is 6 for IPv6 packets.
    /// 2. Traffic Class (8 bits): The traffic class field in the IPv6 header used for QoS management.
    /// 3. Flow Label (20 bits): Used by a source to label sequences of packets for which it requests special handling by the IPv6 routers.
    ///
    /// # Parameters
    /// - `cursor`: A mutable reference to a cursor which is expected to be at the position of the 32-bit segment
    ///   containing the version, traffic class, and flow label in the IPv6 header.
    ///
    /// # Returns
    /// If successful, returns a tuple of `u8` and `u32` integers representing the version, traffic class, and flow label respectively.
    /// If there is an error reading from the cursor, a `ParserError` will be returned.
    ///
    /// # Errors
    /// Returns `ParserError` if there is any issue in reading data from the cursor.
    fn extract_ipv6_version_trafficclass_flowlabel(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(u8, u8, u32), ParserError> {
        // Read the first 32 bits, that contains the `version`, `traffic class` and `flow label`
        let first_32_bits = read_u32(cursor, "Version_TrafficClass_FlowLabel")?;

        // The version is contained in the highest 4 bits of the 32-bit word.
        // Shift by 28 bits to the right to drop the lower 28 bits.
        let version = (first_32_bits >> 28) as u8;

        // The traffic class is in the next 8 bits. Shift 20 bits to the right to drop the lower
        // 20 bits (flow label), and then mask to get only the lower 8 bits.
        let traffic_class = ((first_32_bits >> 20) & 0xFF) as u8;

        // The flow label is in the lowest 20 bits of the 32-bit word.
        let flow_label = first_32_bits & 0xFFFFF; // Masking the lowest 20 bits.

        Ok((version, traffic_class, flow_label))
    }

    /// Extracts specific details from the second 32 bits of the IPv6 header.
    ///
    /// This function is responsible for parsing the next 32 bits after the initial segment of the IPv6 header.
    /// It retrieves the payload length, the identifier of the next header, and the hop limit from the raw header data.
    ///
    /// # Parameters
    /// - `cursor`: A mutable reference to a cursor over the byte slice of the packet. It should be positioned at the start of the 32 bits containing the relevant data.
    ///
    /// # Returns
    /// If successful, returns a tuple of three elements:
    /// - `payload_length`: The length of the IPv6 payload (data coming after the header).
    /// - `next_header`: An identifier for the next header in the packet data. This informs how to interpret the subsequent payload or extension.
    /// - `hop_limit`: The limit of how many hops (routers) this packet can pass through before being discarded.
    ///
    /// If there is an error during parsing, this function returns a `ParserError`.
    ///
    /// # Errors
    /// This function will return an error if reading from the byte slice fails,
    ///  for instance, if there are fewer bytes available than expected.
    fn extract_ipv6_length_header_hoplimit(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(u16, u8, u8), ParserError> {
        // Read the next 32 bits, that contains the `version`, `traffic class` and `flow label`
        let second_32_bits = read_u32(cursor, "PayloadLength_NextHeader_HopLimit")?;

        // The payload length is contained in the highest 16 bits of the 32-bit word.
        // Shift by 16 bits to the right to drop the lower 16 bits.
        let payload_length = (second_32_bits >> 16) as u16;

        // The next header is in the next 8 bits. Shift 8 bits to the right to drop the lower
        // 8 bits (hop limit), and then mask to get only the lower 8 bits.
        let next_header = ((second_32_bits >> 8) & 0xFF) as u8;

        // The flow label is in the lowest 208 bits of the 32-bit word.
        let hop_limit = (second_32_bits & 0xFF) as u8; // Masking the lowest 8 bits.

        Ok((payload_length, next_header, hop_limit))
    }

    /// Extracts an IPv6 address from a byte frame starting at a specified offset.
    ///
    /// Given a byte slice representing a frame and an offset within that frame,
    /// this function attempts to extract 16 bytes from the offset, interprets them as
    /// an IPv6 address, and returns the address as an array of eight `u16` segments.
    ///
    /// # Arguments
    ///
    /// * `frame`: A byte slice representing the frame from which to extract the IPv6 address.
    /// * `offset`: The position within `frame` where the 16 bytes representing the IPv6 address begin.
    ///
    /// # Errors
    ///
    /// Returns `ParserError::FrameTooShort` if the `frame` does not contain enough bytes
    /// (i.e., `offset + 16` exceeds the frame's length).
    ///
    /// Returns `ParserError::ExtractionError` if the attempt to build a 16-byte array from
    /// the frame slice fails (which can happen if the slice is not exactly 16 bytes).
    ///
    /// # Return Value
    ///
    /// Returns `Ok([u16; 8])` representing the IPv6 address if the extraction succeeds.
    fn extract_ipv6_address(frame: &[u8], offset: usize) -> Result<[u16; 8], ParserError> {
        if frame.len() < offset + 16 {
            return Err(ParserError::FrameTooShort(frame.len(), 16));
        }

        // Extracting 16 bytes from the frame for the IPv6 address.
        let bytes: [u8; 16] =
            frame[offset..offset + 16]
                .try_into()
                .map_err(|e| ParserError::ExtractionError {
                    source: ErrorSource::TryFromSlice(e),
                    string: "IPv6 Address".to_string(),
                })?;

        // Converting each pair of bytes into a u16 to form the components of the IPv6 address.
        let mut address = [0u16; 8];
        for i in 0..8 {
            address[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        }

        Ok(address)
    }
}
