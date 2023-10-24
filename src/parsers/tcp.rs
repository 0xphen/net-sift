/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

use super::{
    errors::ParserError,
    utils::{read_arbitrary_length, read_u32},
};

use std::io::{Cursor, Seek, SeekFrom};

/// Represents the flags in the control field of a TCP segment.
///
/// Each flag is a boolean value corresponding to a 1-bit field
/// in the control section, indicating the presence (true) or absence (false)
/// of certain optional control information.
#[derive(Debug, PartialEq)]
pub struct Flags {
    pub cwr: bool, // Congestion Window Reduced flag.
    pub ece: bool, // ECN-Echo flag.
    pub urg: bool, // Urgent Pointer field significant flag.
    pub ack: bool, // Acknowledgment field significant flag.
    pub psh: bool, // Push Function flag.
    pub rst: bool, // Reset the connection flag.
    pub syn: bool, // Synchronize sequence numbers flag.
    pub fin: bool, // No more data from sender flag.
}

impl Flags {
    /// Constructs a `Flags` instance from a single byte.
    ///
    /// Each bit in the byte corresponds to a different TCP flag, with the order
    /// and meaning of the flags defined in the TCP standard.
    ///
    /// # Arguments
    ///
    /// * `byte` - The raw 8-bit unsigned integer representing the flag bits.
    pub fn new(byte: u8) -> Self {
        Flags {
            cwr: byte >> 7 & 1 != 0,
            ece: byte >> 6 & 1 != 0,
            urg: byte >> 5 & 1 != 0,
            ack: byte >> 4 & 1 != 0,
            psh: byte >> 3 & 1 != 0,
            rst: byte >> 2 & 1 != 0,
            syn: byte >> 1 & 1 != 0,
            fin: byte & 1 != 0,
        }
    }
}

const MIN_SEGMENT_SIZE: usize = 20;
const OPTIONS_OFFSET: usize = 20;

#[derive(Debug, PartialEq)]
pub struct TCP {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_value: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: Flags,
    pub window_size: u16,
    pub checksum: u16,
    pub urg_pointer: Option<u16>,
    pub data: Vec<u8>,
}

impl TCP {
    pub fn new(segments: &[u8]) -> Result<Self, ParserError> {
        let mut cursor = Cursor::new(segments);

        let (source_port, destination_port) = Self::extract_tcp_ports(&mut cursor)?;
        let sequence_number = read_u32(&mut cursor, "Sequence_Number")?;
        let acknowledgment_value = read_u32(&mut cursor, "Ack_Number")?;

        let (data_offset, reserved, flags, window_size) =
            Self::extract_tcp_offset_flags_window(&mut cursor)?;

        let (checksum, urg_pointer) =
            Self::extract_tcp_checksum_urg_pointer(&mut cursor, flags.urg)?;

        // Get the size of the options field
        let options_size = (data_offset * 32) / 8 - MIN_SEGMENT_SIZE as u8;

        let payload_offset = match options_size {
            0 => OPTIONS_OFFSET,
            _ => {
                let offset = OPTIONS_OFFSET + options_size as usize;
                cursor.seek(SeekFrom::Start(offset as u64)).map_err(|e| {
                    ParserError::CursorError {
                        string: "Options".to_string(),
                        source: e,
                    }
                })?;

                offset
            }
        };

        let data = read_arbitrary_length(&mut cursor, segments.len() - payload_offset, "Data")?;

        Ok(TCP {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_value,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urg_pointer,
            data,
        })
    }

    /// Extracts the source and destination ports from a TCP segment.
    ///
    /// The function reads the first 4 bytes at the cursor's current position,
    /// interpreting the first 2 bytes as the source port and the last 2 bytes as the destination port.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A cursor over the byte slice of the TCP segment.
    ///
    /// # Returns
    ///
    /// * On success, returns `Ok` with a tuple of two `u16` values: the source port and the destination port.
    /// * On failure, returns an `Err` with a `ParserError` variant.
    ///
    /// # Errors
    ///
    /// This function will return an error if it encounters any issue while reading from the byte cursor.
    fn extract_tcp_ports(cursor: &mut Cursor<&[u8]>) -> Result<(u16, u16), ParserError> {
        let bytes = read_u32(cursor, "SrcPort_DestPort")?;

        // The `Source Port` is contained in the highest 16 bits of the 32-bit word
        let src_port = (bytes >> 16) as u16;
        let dest_port = (bytes & 0xFFFF) as u16;

        Ok((src_port, dest_port))
    }

    /// Extracts the Data Offset, Reserved, Flags, and Window Size fields from a segment of the TCP header.
    ///
    /// This function reads a 4-byte sequence from the provided cursor, then decodes and
    /// separates it into the respective fields: Data Offset, Reserved, Flags, and Window Size.
    /// These represent crucial parameters for the TCP header's structure and subsequent data processing.
    ///
    /// # Parameters:
    /// * `cursor`: A cursor over the slice of the TCP segment data, positioned at the
    ///  start of the 4-byte sequence.
    ///
    /// # Returns:
    /// A `Result` which is:
    /// * `Ok` - Tuple of the extracted fields: `(u8, u8, Flags, u16)` representing Data Offset,
    ///  Reserved, Flags, and Window Size respectively.
    /// * `Err` - An error of type `ParserError` that occurred during the reading from the
    /// cursor or the decoding process.
    ///
    /// # Errors:
    /// This function will return an error if there is an issue reading from the provided cursor,
    /// such as if there is insufficient data to comprise a complete 4-byte sequence.
    fn extract_tcp_offset_flags_window(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(u8, u8, Flags, u16), ParserError> {
        let bytes = read_u32(cursor, "DataOffset_Flags_Window")?;

        let data_offset = (bytes >> 28) as u8;
        let reserved = ((bytes >> 24) & 0xF) as u8;
        let flags = Flags::new(((bytes >> 16) & 0xFF) as u8);
        let window = (bytes & 0xFFFF) as u16;

        Ok((data_offset, reserved, flags, window))
    }

    /// Extracts the checksum and potentially the urgent pointer from a TCP segment.
    ///
    /// The function reads a 32-bit value from the provided cursor, which encompasses both the
    /// checksum and the urgent pointer field from the TCP segment. The checksum is always extracted,
    /// whereas the urgent pointer is conditionally extracted based on the value of the `urg` parameter.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A cursor pointing at the slice of bytes representing the TCP segment. It should be
    ///              positioned where the 32-bit segment starting with the checksum is located.
    /// * `urg` - A boolean value indicating whether the urgent pointer field should be considered.
    ///           If true, the function treats the lower 16 bits of the 32-bit segment as the urgent
    ///           pointer and includes it in the return value.
    ///
    /// # Returns
    ///
    /// * On successful read and extraction, returns `Ok` with a tuple. The first element of the tuple
    ///   is a `u16` representing the checksum. The second element is an `Option<u16>`, which is `Some`
    ///   with the urgent pointer value if `urg` is true; otherwise, it is `None`.
    /// * On failure, such as being unable to read enough bytes from the cursor, returns an `Err`
    ///   containing a `ParserError` variant indicating the nature of the error.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an issue reading from the cursor, such as
    /// reaching the end of the byte slice prematurely, which would indicate a malformed TCP segment.
    fn extract_tcp_checksum_urg_pointer(
        cursor: &mut Cursor<&[u8]>,
        urg: bool,
    ) -> Result<(u16, Option<u16>), ParserError> {
        let bytes = read_u32(cursor, "Checksum_UrgPointer")?;

        // Extracting the checksum from the upper 16 bits.
        let checksum = (bytes >> 16) as u16;

        let urg_pointer = if urg {
            Some((bytes & 0xFFFF) as u16)
        } else {
            None
        };

        Ok((checksum, urg_pointer))
    }
}
