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
    definitions::{DeepParser, EtherType, LayeredData},
    errors::ParserError,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    utils::{read_arbitrary_length, read_u128, read_u16},
};

use std::fmt;
use std::io::{Cursor, Seek, SeekFrom};

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

// Constants representing various parameters and offsets within an Ethernet frame.
// These are used for parsing the frame correctly.
const TPID_VLAN: u32 = 33024; // [0x81, 0x00];

#[derive(Debug, PartialEq)]
/// Represents the header of an Ethernet frame.
///
/// Ethernet frames begin with a header that contains the essential fields
/// for network communication. This struct captures the key components of
/// that header, specifically catering to Ethernet II framing.
pub struct EthernetFrameHeader {
    /// The MAC (Media Access Control) address of the intended recipient of the packet.
    pub mac_destination: MacAddress,

    /// The MAC address of the sender of the packet.
    pub mac_source: MacAddress,

    /// An optional 802.1Q tag specifying VLAN membership and priority information.
    /// It's present in VLAN-tagged frames, otherwise `None`.
    pub q_tag: Option<u32>,

    /// The EtherType field indicating the protocol encapsulated in the payload of the frame.
    /// Common values indicate IPv4, IPv6, ARP, etc.
    pub ether_type: EtherType,
}

/// Represents a complete Ethernet frame.
///
/// This structure encompasses the entire Ethernet frame, providing access to
/// both the header and the payload of the frame. It is fundamental for
/// handling network data at a low level, allowing for the parsing, creation,
/// and manipulation of Ethernet frames for various networking operations.
#[derive(Debug, PartialEq)]
pub struct EthernetFrame {
    /// The header of the Ethernet frame, containing all the relevant
    /// information for routing and type of content.
    pub header: EthernetFrameHeader,

    /// The actual payload of the Ethernet frame encapsulated as `LayeredData`.
    /// This can represent various forms of data as structured in different
    /// network layers, depending on the EtherType specified in the header.
    pub data: Box<LayeredData>,
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
    pub fn from_bytes(frame: &[u8]) -> Result<Self, ParserError> {
        if frame.len() < constants::MIN_FRAME_SIZE {
            return Err(ParserError::InvalidLength);
        }
        let mut cursor: Cursor<&[u8]> = Cursor::new(frame);

        let (mac_destination, mac_source, q_tag, ether_type) = Self::extract_header(&mut cursor)?;

        let data = read_arbitrary_length(
            &mut cursor,
            Self::data_size(frame.len(), q_tag),
            "EtherFrame_Data",
        )?;

        Ok(EthernetFrame {
            header: EthernetFrameHeader {
                mac_destination,
                mac_source,
                q_tag,
                ether_type,
            },
            data: Box::new(LayeredData::Payload(data)),
        })
    }

    /// Extracts the Ethernet frame header from a byte stream.
    ///
    /// This function parses the destination and source MAC addresses, optional VLAN tag (QTag),
    /// and EtherType from the provided byte stream accessed via a cursor.
    ///
    /// # Parameters
    /// * `cursor`: A mutable reference to a cursor over the byte slice containing the Ethernet frame.
    ///
    /// # Returns
    /// * `Ok((MacAddress, MacAddress, Option<u32>, EtherType))`: A tuple containing the destination MAC
    ///   address, the source MAC address, an optional VLAN tag (QTag), and the EtherType if successful.
    /// * `Err(ParserError)`: An error if the header could not be parsed, which could be due to
    ///   insufficient data, unrecognized EtherType, or other parsing issues.
    ///
    /// # Errors
    /// This function will return an error if the byte slice does not contain enough data for a
    /// complete Ethernet header, if the EtherType is not one of the accepted types, or if any
    /// other parsing issue occurs.
    fn extract_header(
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(MacAddress, MacAddress, Option<u32>, EtherType), ParserError> {
        let bytes = read_u128(cursor, "Ethernet_Header")?;
        let mac_dest = Self::extract_mac_address(((bytes >> 80) & 0xFFFFFFFFFFFF) as u64);
        let mac_src = Self::extract_mac_address(((bytes >> 32) & 0xFFFFFFFFFFFF) as u64);
        let leftover_bytes = (bytes & 0xFFFFFFFF) as u32;

        let (q_tag, ether_type) = match leftover_bytes >> 16 {
            TPID_VLAN => {
                let ether_type = read_u16(cursor, "Ether_Type")?;
                (Some(leftover_bytes), ether_type)
            }
            _ => {
                // QTag isn't present in the frame, hence we move the cursor
                // back 2 positions.
                cursor.set_position(cursor.position() - 2);
                (None, (leftover_bytes >> 16) as u16)
            }
        };

        if !constants::ACCEPTED_ETHERTYPES.contains(&ether_type.to_be_bytes()) {
            return Err(ParserError::InvalidEtherType);
        }

        Ok((mac_dest, mac_src, q_tag, EtherType::from(ether_type)))
    }

    /// Extracts a MAC address from a 64-bit integer.
    ///
    /// The MAC address is assumed to be in the lower 48 bits of the value,
    /// in big-endian order. This function reads the individual bytes that
    /// make up the MAC address and returns a `MacAddress` instance.
    ///
    /// # Arguments
    ///
    /// * `value` - A `u64` value containing the MAC address in its lower 48 bits.
    ///
    /// # Returns
    ///
    /// A `MacAddress` instance created from the extracted bytes.
    fn extract_mac_address(value: u64) -> MacAddress {
        // The MAC address lies in the 48 LSBs.
        let bytes: [u8; 6] = [
            ((value >> 40) & 0xFF) as u8,
            ((value >> 32) & 0xFF) as u8,
            ((value >> 24) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ];

        MacAddress::from_bytes(bytes)
    }

    fn data_size(frame_size: usize, q_tag: Option<u32>) -> usize {
        let header_size_without_q_tag = 14; // Header size (excluding the VLAN field) is 14 bytes
        let vlan_tag_size = q_tag.map_or(0, |_| 4); // VLAN tag is 4 bytes if present
        let fcs_size = 4; // Frame Check Sequence is 4 bytes

        // Calculate payload size by subtracting the header size and FCS from the frame size
        frame_size - (header_size_without_q_tag + vlan_tag_size + fcs_size)
    }
}

impl DeepParser for EthernetFrame {
    fn parse_next_layer(mut self) -> Result<LayeredData, ParserError> {
        let data = match &*self.data {
            LayeredData::Payload(data) => data,
            _ => return Err(ParserError::InvalidPayload),
        };

        let layered_data = match self.header.ether_type {
            EtherType::IPv4 => {
                let ipv4_packet = Ipv4Packet::from_bytes(data)?;
                ipv4_packet.parse_next_layer()?
            }
            EtherType::IPv6 => {
                let ipv6_packet = Ipv6Packet::from_bytes(data)?;
                ipv6_packet.parse_next_layer()?
            }
            _ => return Err(ParserError::UnSupportedEtherType),
        };

        *self.data = layered_data;
        Ok(LayeredData::EthernetFrameData(self))
    }
}
