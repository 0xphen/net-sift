/*
 *  ICMP Packet Structure:
 *
 *  0               8               16                             31
 *  +---------------+---------------+------------------------------+
 *  |   Type (8)    |   Code (8)    |        Checksum (16)         |
 *  +---------------+---------------+------------------------------+
 *  |                                                               |
 *  |                 Message Body (variable length)                |
 *  |                                                               |
 *  +---------------------------------------------------------------+
 */

use super::{
    definitions::{DeepParser, LayeredData},
    errors::ParserError,
    utils::{read_arbitrary_length, read_u64},
};

use std::io::Cursor;

const DATA_OFFSET_OR_MIN_SIZE: usize = 8;

#[derive(Debug, PartialEq)]
pub struct IcmpPacketHeader {
    pub icmp_type: u8,       // Type of ICMP message.
    pub icmp_code: u8,       // Subtype to further specify the message.
    pub checksum: u16,       // Error-checking data calculated from the ICMP message.
    pub rest_of_header: u32, // Remaining data in the header (depends on type and code).
}

#[derive(Debug, PartialEq)]
pub struct IcmpPacket {
    pub header: IcmpPacketHeader,
    pub data: Box<LayeredData>,
}

impl IcmpPacket {
    /// Constructs a new IcmpPacket from a slice of bytes.
    ///
    /// The function expects a byte slice representing a full ICMP packet and returns an
    /// IcmpPacket instance or an error if the packet is malformed.
    ///
    /// # Arguments:
    ///
    /// * `packets` - A byte slice containing the ICMP packet data.
    ///
    /// # Returns:
    ///
    /// * `Result<Self, ParserError>` - An IcmpPacket instance or a ParserError.
    pub fn from_bytes(packets: &[u8]) -> Result<Self, ParserError> {
        if packets.len() < DATA_OFFSET_OR_MIN_SIZE {
            return Err(ParserError::InvalidLength);
        }

        let mut cursor = Cursor::new(packets);

        let (icmp_type, icmp_code, checksum, rest_of_header) =
            Self::extract_icmp_header_fields(&mut cursor)?;

        let data = read_arbitrary_length(
            &mut cursor,
            packets.len() - DATA_OFFSET_OR_MIN_SIZE,
            "ICMP_Data",
        )?;

        Ok(IcmpPacket {
            header: IcmpPacketHeader {
                icmp_type,
                icmp_code,
                checksum,
                rest_of_header,
            },
            data: Box::new(LayeredData::Payload(data)),
        })
    }

    /// Extracts fields from the ICMP header.
    ///
    /// This function reads the first 8 bytes of an ICMP message, parses the bytes, and extracts the
    /// type, code, checksum, and the rest of the header fields. Note that the actual structure of
    /// the rest of the header can vary depending on the ICMP message type and code.
    ///
    /// # Parameters:
    /// * `cursor`: A mutable reference to a cursor positioned at the start of the ICMP header in
    ///   a byte slice.
    ///
    /// # Returns:
    /// * `Ok((u8, u8, u16, u32))`: A tuple containing the ICMP type, code, checksum, and the
    ///   rest of the header as a 32-bit value. The exact structure of the rest of the header
    ///   depends on the type and code.
    /// * `Err(ParserError)`: An error occurred during reading from the byte stream, possibly
    ///   because the stream ended prematurely.
    fn extract_icmp_header_fields(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(u8, u8, u16, u32), ParserError> {
        let bytes = read_u64(cursor, "Type_Code_Checksum_Header")?;

        let icmp_type = (bytes >> 56) as u8;
        let icmp_code = ((bytes >> 48) & 0xFF) as u8;
        let checksum = ((bytes >> 32) & 0xFFFF) as u16;
        let rest_of_header = (bytes & 0xFFFFFFFF) as u32;

        Ok((icmp_type, icmp_code, checksum, rest_of_header))
    }
}

impl DeepParser for IcmpPacket {
    fn parse_next_layer(self) -> Result<LayeredData, ParserError> {
        Ok(LayeredData::IcmpData(self))
    }
}
