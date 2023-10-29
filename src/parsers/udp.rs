/*
 *  0      7 8     15 16    23 24    31
 *  +--------+--------+--------+--------+
 *  |     Source      |   Destination   |
 *  |      Port       |       Port      |
 *  +--------+--------+--------+--------+
 *  |                 |                 |
 *  |     Length      |    Checksum     |
 *  +--------+--------+--------+--------+
 *  |
 *  |          ...Data Payload...
 *  +---------------- ...
 */

use super::{
    definitions::{DeepParser, LayeredData},
    errors::ParserError,
    utils::{read_arbitrary_length, read_u64},
};

use std::io::Cursor;

const DATA_OFFSET_OR_MIN_SIZE: usize = 8;

#[derive(Debug, PartialEq)]
pub struct UdpDatagramHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, PartialEq)]
pub struct UdpDatagram {
    pub header: UdpDatagramHeader,
    pub data: Box<LayeredData>,
}

impl UdpDatagram {
    /// Parses the given UDP packet byte slice and constructs a `UDP` structure.
    ///
    /// This function will read the header fields such as source and destination ports,
    /// packet length, and checksum. It then extracts the data payload based on the
    /// length specified in the header.
    ///
    /// # Parameters:
    /// * `packets`: The UDP packet data as a byte slice.
    ///
    /// # Returns:
    /// * `Ok(UDP)`: A `UDP` structure containing the parsed packet information.
    /// * `Err(ParserError)`: An error occurred during parsing, which could be due to
    ///   invalid packet structure, insufficient data, etc.
    ///
    /// # Errors:
    /// The function will return an error in cases such as:
    /// * The packet data is shorter than the UDP header size.
    /// * The indicated packet length is inconsistent with the actual data length.
    pub fn from_bytes(packets: &[u8]) -> Result<Self, ParserError> {
        if packets.len() < DATA_OFFSET_OR_MIN_SIZE {
            return Err(ParserError::InvalidLength);
        }

        let mut cursor = Cursor::new(packets);

        let (source_port, destination_port, length, checksum) =
            Self::extract_udp_header_fields(&mut cursor)?;

        let data = read_arbitrary_length(
            &mut cursor,
            packets.len() - DATA_OFFSET_OR_MIN_SIZE,
            "UDP_Data",
        )?;

        Ok(UdpDatagram {
            header: UdpDatagramHeader {
                source_port,
                destination_port,
                length,
                checksum,
            },
            data: Box::new(LayeredData::Payload(data)),
        })
    }

    /// Parses the UDP header from a segment and extracts the essential fields.
    ///
    /// This function reads the first eight bytes from the provided segment—represented by a cursor
    /// in the byte stream—and extracts the source port, destination port, length, and checksum.
    ///
    /// The cursor should be at the position where the UDP header starts, and the segment must contain
    /// at least eight bytes from that position. The function does not handle the data payload of the
    /// UDP segment; it only deals with the header information.
    ///
    /// # Parameters
    /// * `cursor`: A mutable reference to a cursor, which points to the start of a byte slice that
    ///   contains the UDP header. The cursor's position updates to after the header once the function
    ///   executes.
    ///
    /// # Returns
    /// * `Ok((u16, u16, u16, u16))`: If the function succeeds, it returns a tuple containing the
    ///   source port, destination port, length, and checksum, all as unsigned 16-bit integers.
    /// * `Err(ParserError)`: If the function encounters an issue while reading the byte stream, it
    ///   returns an error. Potential errors can arise from the cursor having insufficient data (less
    ///   than eight bytes) or issues with the byte stream itself.
    fn extract_udp_header_fields(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(u16, u16, u16, u16), ParserError> {
        let bytes = read_u64(cursor, "SrcPort_DestPort_Length_Checksum")?;

        let src_port = (bytes >> 48) as u16;
        let dest_port = ((bytes >> 32) & 0xFFFF) as u16;
        let length = ((bytes >> 16) & 0xFFFF) as u16;
        let checksum = (bytes & 0xFFFF) as u16;

        Ok((src_port, dest_port, length, checksum))
    }
}

impl DeepParser for UdpDatagram {
    fn parse_next_layer(self) -> Result<LayeredData, ParserError> {
        Ok(LayeredData::UdpData(self))
    }
}
