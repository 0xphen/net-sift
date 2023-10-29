use std::io::{Cursor, Read};

use super::{
    definitions::{DeepParser, IPType, LayeredData},
    errors::{ErrorSource, ParserError},
    icmp::IcmpPacket,
    tcp::TcpSegment,
    udp::UdpDatagram,
};

/// Reads an arbitrary number of bytes from a cursor within a byte slice.
///This function attempts to read 'length' number of bytes from
/// the provided cursor's current position and returns those bytes
/// as a vector. It advances the cursor's position by the number
///  of bytes read. In case of an error during the read operation,
/// it returns a `ParserError`, providing information about the
/// source of the error and the field being read.
///
/// # Parameters
/// - `cursor`: A mutable reference to a cursor over the byte slice
///  from which the data is read.
///  The cursor is advanced by 'length' bytes if the operation is successful.
/// - `length`: The number of bytes to read from the current
///  cursor position. The function allocates a buffer of this
///  size to store the read bytes.
/// - `field`: A reference to a string that describes the field
///  being read. This is used for error reporting purposes to specify
///  which field encountered a read error.
///
/// # Returns
/// - `Ok`: If the read operation is successful, it returns the
/// bytes read as a `Vec<u8>`.
/// - `Err`: If the read operation fails (for example, trying
///  to read beyond the end of the byte slice), it returns a
///  `ParserError` with relevant error information.
pub fn read_arbitrary_length(
    cursor: &mut Cursor<&[u8]>,
    length: usize,
    field: &str,
) -> Result<Vec<u8>, ParserError> {
    let mut buffer = vec![0; length];

    cursor
        .read_exact(&mut buffer)
        .map_err(|e| ParserError::ExtractionError {
            source: ErrorSource::Io(e),
            string: field.to_string(),
        })?;

    Ok(buffer)
}

pub fn read_u32(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u32, ParserError> {
    let mut buffer: [u8; 4] = Default::default();

    cursor
        .read_exact(&mut buffer)
        .map_err(|e| ParserError::ExtractionError {
            string: field.to_string(),
            source: ErrorSource::Io(e),
        })?;

    Ok(u32::from_be_bytes(buffer))
}

pub fn read_u64(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u64, ParserError> {
    let mut buffer: [u8; 8] = Default::default();

    cursor
        .read_exact(&mut buffer)
        .map_err(|e| ParserError::ExtractionError {
            string: field.to_string(),
            source: ErrorSource::Io(e),
        })?;

    Ok(u64::from_be_bytes(buffer))
}

pub fn read_u16(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u16, ParserError> {
    let mut buffer: [u8; 2] = Default::default();

    cursor
        .read_exact(&mut buffer)
        .map_err(|e| ParserError::ExtractionError {
            string: field.to_string(),
            source: ErrorSource::Io(e),
        })?;

    Ok(u16::from_be_bytes(buffer))
}

pub fn read_u8(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u8, ParserError> {
    let mut buffer: [u8; 1] = Default::default();

    cursor
        .read_exact(&mut buffer)
        .map_err(|e| ParserError::ExtractionError {
            source: ErrorSource::Io(e),
            string: field.to_string(),
        })?;

    Ok(u8::from_be_bytes(buffer))
}

/// Parses the encapsulated protocol layer within the payload of an IPv4 or IPv6 packet.
///
/// The function decodes the payload based on the specified `IPType` (e.g., TCP, UDP, ICMP) and
/// returns the parsed data as `LayeredData` or an error if the parsing fails.
///
/// # Arguments
///
/// * `payload` - A `LayeredData` instance containing the payload data to parse.
/// * `ip_type` - An `IPType` enum indicating the protocol type contained in the payload.
///
/// # Returns
///
/// * `Ok(LayeredData)` containing the parsed protocol data if parsing is successful.
/// * `Err(ParserError)` if there is an error during parsing.
pub fn parse_ip_next_protocol_layer(
    payload: &LayeredData,
    ip_type: &IPType,
) -> Result<LayeredData, ParserError> {
    if let LayeredData::Payload(data) = payload {
        let layered_data = match ip_type {
            IPType::TCP => {
                let tcp_packet = TcpSegment::from_bytes(data)?;
                tcp_packet.parse_next_layer()
            }
            IPType::UDP => {
                let udp_datagram = UdpDatagram::from_bytes(data)?;
                udp_datagram.parse_next_layer()
            }
            IPType::ICMP => {
                let icmp_packet = IcmpPacket::from_bytes(data)?;
                icmp_packet.parse_next_layer()
            }
            IPType::Other(v) => Err(ParserError::UnknownIPType(*v)),
        }?;

        Ok(layered_data)
    } else {
        return Err(ParserError::InvalidPayload);
    }
}
