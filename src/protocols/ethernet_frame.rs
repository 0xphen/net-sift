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

use super::{constants, errors::EthernetFrameError};

const MAC_ADDRESS_BYTES: usize = 6;

/// Represents a MAC address.
#[derive(Debug)]
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

    /// Converts the MAC address to its string representation.
    ///
    /// # Returns
    ///
    /// * A string representation of the MAC address in the format `XX:XX:XX:XX:XX:XX`.
    pub fn to_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Tag Protocol Identifier for VLAN-tagged frames.
const TPID_VLAN: [u8; 2] = [0x81, 0x00];

/// Offset for the destination MAC address in an Ethernet frame.
const OFFSET_MAC_DEST: usize = 0;

/// Offset for the source MAC address in an Ethernet frame.
const OFFSET_MAC_SRC: usize = 6;

/// Offset for the TPID in an Ethernet frame, potentially indicating a VLAN tag.
const OFFSET_TPID: usize = 12;

/// Represents the structure of an Ethernet frame.
#[derive(Debug)]
pub struct EthernetFrame {
    /// Destination MAC address of the frame.
    pub mac_destination: MacAddress,

    /// Source MAC address of the frame.
    pub mac_source: MacAddress,

    /// Optional Q-tag, present in VLAN-tagged frames. Includes TPID and TCI.
    pub q_tag: Option<[u8; 4]>,

    /// EtherType field indicating the upper-layer protocol.
    pub ether_type: [u8; 2],

    pub payload: Vec<u8>,

    pub fcs: [u8; 4],
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
    pub fn new(frame: Vec<u8>) -> Result<Self, EthernetFrameError> {
        if frame.len() < constants::MIN_FRAME_SIZE {
            return Err(EthernetFrameError::InvalidEthernetFrame(frame.len()));
        }

        // Directly extract potential MAC addresses and EtherType
        let mac_destination_bytes: [u8; 6] = frame[OFFSET_MAC_DEST..OFFSET_MAC_DEST + 6]
            .try_into()
            .map_err(|e| EthernetFrameError::MacAddressExtractionError { source: e })?;

        let mac_source_bytes: [u8; 6] = frame[OFFSET_MAC_SRC..OFFSET_MAC_SRC + 6]
            .try_into()
            .map_err(|e| EthernetFrameError::MacAddressExtractionError { source: e })?;

        let (q_tag, ether_type_offset) = match &frame[OFFSET_TPID..OFFSET_TPID + 2] {
            [81, 00] => {
                let q_tag_bytes: [u8; 4] = frame[OFFSET_TPID..OFFSET_TPID + 4]
                    .try_into()
                    .map_err(|e| EthernetFrameError::QTagExtractionError { source: e })?;
                (Some(q_tag_bytes), OFFSET_TPID + 4)
            }
            _ => (None, OFFSET_TPID),
        };

        let ether_type: [u8; 2] = frame[ether_type_offset..ether_type_offset + 2]
            .try_into()
            .map_err(|e| EthernetFrameError::EtherTypeExtractionError { source: e })?;

        if !constants::ACCEPTED_ETHERTYPES.contains(&ether_type) {
            return Err(EthernetFrameError::InvalidEtherType);
        }

        let fcs = frame[frame.len().saturating_sub(4)..frame.len()]
            .try_into()
            .map_err(|e| EthernetFrameError::FCSExtractionError { source: e })?;

        Ok(EthernetFrame {
            mac_destination: MacAddress::from_bytes(mac_destination_bytes),
            mac_source: MacAddress::from_bytes(mac_source_bytes),
            q_tag,
            ether_type,
            fcs,
            payload: frame[ether_type_offset + 2..(frame.len() - 4)].to_vec(),
        })
    }
}
