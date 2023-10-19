// Ethernet II Frame Structure:
// +---------------------------+
// | Preamble (7 bytes)        |
// +---------------------------+
// | Start Frame Delimiter (1) |
// +---------------------------+
// | Destination MAC (6 bytes) |
// +---------------------------+
// | Source MAC (6 bytes)      |
// +---------------------------+
// | EtherType (2 bytes)       |
// +---------------------------+
// | Payload (46-1500 bytes)   |
// +---------------------------+
// | FCS (4 bytes)             |
// +---------------------------+

use super::{
    constants,
    errors::{ErrorSource, ParserError},
    utils::read_arbitrary_length,
};

use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom};

const MAC_ADDRESS_BYTES: usize = 6;

/// A struct representing a Media Access Control (MAC) address, used for identifying network hardware.
///
/// It contains a single field, a 6-byte array, as MAC addresses are 6 bytes in length.
#[derive(Debug, PartialEq)]
pub struct MacAddress(pub [u8; MAC_ADDRESS_BYTES]);

impl MacAddress {
    /// Constructs a `MacAddress` from a 6-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 6-byte array representing the MAC address.
    ///
    /// # Returns
    ///
    /// * A new `MacAddress` instance.
    pub fn from_bytes(bytes: [u8; MAC_ADDRESS_BYTES]) -> Self {
        MacAddress(bytes)
    }
}

impl fmt::Display for MacAddress {
    /// Formats the MAC address for display purposes.
    /// This implementation will print the MAC address in the common hex notation, separated by colons.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,
            0x86DD => Self::IPv6,
            0x0806 => Self::ARP,
            other => Self::Other(other),
        }
    }
}

// Constants representing various parameters and offsets within an Ethernet frame.
// These are used for parsing the frame correctly.
const TPID_VLAN: u32 = 33024; // [0x81, 0x00];
const Q_TAG_OR_ETHER_TYPE_OFFSET: u64 = 12;
const BITMASK_Q_TAG: u32 = 0xFFFFFFFF;
const OFFSET_MAC_DEST: usize = 0;
const OFFSET_MAC_SRC: usize = 6;

/// An Ethernet frame representation.
///
/// The `EthernetFrame` struct models the structure of an Ethernet II frame,
/// which is the most commonly used Ethernet frame type. The Ethernet frame
/// carries data internally for protocols such as IP and ARP.
///
/// An Ethernet frame comprises several fields including destination and
/// source MAC addresses, an optional VLAN tag (Q-tag), an EtherType field
/// indicating the upper-layer protocol, the payload, and a Frame Check Sequence (FCS).
///
/// # Fields
///
/// * `mac_destination`: The MAC address of the receiving device.
/// * `mac_source`: The MAC address of the sending device.
/// * `q_tag`: An optional Q-tag field used in VLANs. If the frame is VLAN-tagged,
///   this field will include the Tag Protocol Identifier (TPID) and the Tag Control Information (TCI).
/// * `ether_type`: A field that indicates the protocol of the encapsulated payload.
///   For example, `0x0800` indicates IPv4.
/// * `payload`: The encapsulated data within the Ethernet frame. Its content and interpretation
///   are determined by the `ether_type`.
/// Note: The Frame Check Sequence (FCS) is not represented here as
/// it's used only for the frame's integrity check.
#[derive(Debug)]
pub struct EthernetFrame {
    pub mac_destination: MacAddress, // Destination MAC address
    pub mac_source: MacAddress,      // Source MAC address
    pub q_tag: Option<u32>,          // Optional Q-tag for VLAN-tagged frames
    pub ether_type: EtherType,       // EtherType indicating the upper-layer protocol
    pub payload: Vec<u8>,            // Frame's payload/data
}

impl EthernetFrame {
    /// Constructs an `EthernetFrame` from the given raw byte data.
    ///
    /// This function parses the raw byte data representing an Ethernet frame,
    /// extracts relevant parts (such as MAC addresses, potential Q-tag, and EtherType),
    /// and returns an `EthernetFrame` instance.
    ///
    /// The function expects the raw data to be structured according to standard Ethernet
    /// frame formats and checks for the presence of an IEEE 802.1Q VLAN tag (Q-tag).
    /// If such a tag is detected, it adjusts the extraction offsets accordingly.
    ///
    /// # Arguments
    ///
    /// * `data` - A `Vec<u8>` containing the raw byte data of the Ethernet
    /// frame. The vector
    ///   should at least contain bytes representing destination MAC, source
    /// MAC, and EtherType.
    ///   If a Q-tag is present, the vector's length should account for it as
    /// well.
    ///
    /// # Panics
    ///
    /// The function will panic in the following scenarios:
    ///
    /// * If the provided data does not have the expected minimum length.
    /// * If the data structure doesn't match expected positions for MAC
    /// addresses or EtherType.
    ///
    /// # Returns
    ///
    /// Returns an `EthernetFrame` instance populated with the extracted data.
    pub fn new(frame: &[u8]) -> Result<Self, ParserError> {
        if frame.len() < constants::MIN_FRAME_SIZE {
            return Err(ParserError::FrameTooShort(
                frame.len(),
                constants::MIN_FRAME_SIZE,
            ));
        }

        let mac_destination_bytes: [u8; 6] =
            EthernetFrame::extract_mac_address(&frame, OFFSET_MAC_DEST)?;

        let mac_source_bytes: [u8; 6] = Self::extract_mac_address(&frame, OFFSET_MAC_SRC)?;

        let mut cursor: Cursor<&[u8]> = Cursor::new(frame);
        // Since we already extracted the MAC addresses, we move the cursor
        // to the next index after the MAC addresses.
        cursor
            .seek(SeekFrom::Start(Q_TAG_OR_ETHER_TYPE_OFFSET))
            .map_err(|e| ParserError::CursorError {
                string: "Options".to_string(),
                source: e,
            })?;

        let q_tag_ether_bytes = Self::read_u32(&mut cursor, "QTAG_&_ETHERTYPE")?;

        let (q_tag, ether_type) =
            Self::parse_vlan_tag_and_ether_type(&mut cursor, q_tag_ether_bytes)?;

        let fcs_offset = frame.len() - 4;
        let payload_size = fcs_offset as u64 - cursor.position();
        let payload = read_arbitrary_length(&mut cursor, payload_size as usize, "Payload")?;

        Ok(EthernetFrame {
            mac_destination: MacAddress::from_bytes(mac_destination_bytes),
            mac_source: MacAddress::from_bytes(mac_source_bytes),
            q_tag,
            ether_type: EtherType::from(ether_type),
            payload,
        })
    }

    /// Parses the VLAN tag (if present) and the EtherType from a segment of network packet data.
    ///
    /// Given a cursor reference within a network packet and a 4-byte segment that potentially contains
    /// VLAN tagging information (Q-tag) and EtherType, this function discerns whether a VLAN tag is
    /// present and extracts the EtherType. It adjusts the cursor position based on the presence of the
    /// VLAN tag.
    ///
    /// The function operates by examining the two higher-order bytes of `q_tag_ether_bytes` for the
    /// VLAN TPID. If the TPID indicates a VLAN tag, the tag is extracted along with the EtherType.
    /// If not, the cursor is adjusted, assuming the two bytes are part of the EtherType, not a VLAN tag.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A mutable reference to a cursor positioned at the relevant segment
    ///  of a network packet data slice.
    /// * `q_tag_ether_bytes` - A 32-bit value possibly containing a VLAN tag and EtherType,
    ///  specifically the two bytes for the potential tag and two bytes for the EtherType.
    ///
    /// # Returns
    ///
    /// This function returns a tuple containing two elements wrapped in `Result`:
    /// * `Option<u32>` - The VLAN tag present as a 32-bit value, or `None` if a VLAN tag isn't found.
    /// * `u16` - The 16-bit EtherType value extracted from the packet data.
    fn parse_vlan_tag_and_ether_type(
        cursor: &mut Cursor<&[u8]>,
        q_tag_ether_bytes: u32,
    ) -> Result<(Option<u32>, u16), ParserError> {
        let (q_tag, ether_type) = match q_tag_ether_bytes >> 16 {
            TPID_VLAN => {
                let e_t = Self::read_u16(cursor, "Ether Type")?;
                (Some(q_tag_ether_bytes & BITMASK_Q_TAG), e_t)
            }
            _ => {
                // QTag isn't present in the frame, hence we move the cursor
                // back 2 positions.
                cursor.set_position(cursor.position() - 2);
                (None, (q_tag_ether_bytes >> 16) as u16)
            }
        };

        if !constants::ACCEPTED_ETHERTYPES.contains(&ether_type.to_be_bytes()) {
            return Err(ParserError::InvalidEtherType);
        }

        Ok((q_tag, ether_type))
    }

    /// Extracts a MAC address from the ethernet frame based on a specified offset.
    ///
    /// The function attempts to retrieve a MAC address, typically used for
    /// either source or destination MAC extraction, starting from the given offset.
    ///
    /// # Arguments
    ///
    /// * `frame` - The byte slice representing the ethernet frame.
    /// * `offset` - Starting index within `frame` where the MAC address is expected to begin.
    ///
    /// # Returns
    ///
    /// * `Ok` with the MAC address as a byte array if extraction is successful.
    /// * `Err` with an associated `EthernetFrameError` detailing the cause of the failure.
    ///
    /// # Errors
    ///
    /// * `EthernetFrameError::InvalidMacBytes` if the frame doesn't contain
    /// enough bytes from the offset to extract a MAC address.
    /// * `EthernetFrameError::MacAddressExtractionError` if there's an issue
    ///  during the extraction process.
    fn extract_mac_address(frame: &[u8], offset: usize) -> Result<[u8; 6], ParserError> {
        if frame.len() < offset + 6 {
            return Err(ParserError::FrameTooShort(frame.len(), 6));
        }

        frame[offset..offset + 6]
            .try_into()
            .map_err(|e| ParserError::ExtractionError {
                source: ErrorSource::TryFromSlice(e),
                string: "Src/Dest MAC Address".to_string(),
            })
    }

    /// Reads a 128-bit unsigned integer from the current position of the cursor in big-endian format.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A cursor over the byte slice from which the data will be read.
    /// * `field` - A description of the data field, used for error messages.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `u128` value if successful, otherwise a `ParserError::ExtractionError`.
    fn read_u32(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u32, ParserError> {
        let mut buffer: [u8; 4] = Default::default();

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                string: field.to_string(),
                source: ErrorSource::Io(e),
            })?;

        Ok(u32::from_be_bytes(buffer))
    }

    /// Reads a 16-bit unsigned integer from the cursor's current position in big-endian format.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A reference to the cursor in the byte slice being read.
    /// * `field` - A descriptor for the data field, used in error messaging.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `u16` value if successful, or a `ParserError::ExtractionError` on failure.
    fn read_u16(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u16, ParserError> {
        let mut buffer: [u8; 2] = Default::default();

        cursor
            .read_exact(&mut buffer)
            .map_err(|e| ParserError::ExtractionError {
                string: field.to_string(),
                source: ErrorSource::Io(e),
            })?;

        Ok(u16::from_be_bytes(buffer))
    }

    // /// Extracts a MAC address from a 64-bit integer, ignoring the 2 most significant bytes.
    // ///
    // /// The function focuses on the 48 bits that represent the MAC address, skipping the first 16 bits.
    // ///
    // /// # Arguments
    // ///
    // /// * `v` - A 64-bit integer containing the MAC address in the 48 least significant bits.
    // ///
    // /// # Returns
    // ///
    // /// A 6-element byte array representing the MAC address.
    // fn extract_mac_address(v: u64) -> [u8; 6] {
    //     [
    //         (v >> 40) as u8,
    //         ((v >> 32) & 0xFF) as u8,
    //         ((v >> 24) & 0xFF) as u8,
    //         ((v >> 16) & 0xFF) as u8,
    //         ((v >> 8) & 0xFF) as u8,
    //         (v & 0xFF) as u8,
    //     ]
    // }
}
