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

use std::fmt;

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
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
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
/// * `fcs`: The Frame Check Sequence (FCS) for error-checking. It's typically used to check the
///   integrity of the transmitted data.
#[derive(Debug)]
pub struct EthernetFrame {
    pub mac_destination: MacAddress, // Destination MAC address
    pub mac_source: MacAddress,      // Source MAC address
    pub q_tag: Option<[u8; 4]>,      // Optional Q-tag for VLAN-tagged frames
    pub ether_type: [u8; 2],         // EtherType indicating the upper-layer protocol
    pub payload: Vec<u8>,            // Frame's payload/data
    pub fcs: [u8; 4],                // Frame Check Sequence for error-checking
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
        let mac_destination_bytes: [u8; 6] =
            EthernetFrame::extract_mac_address(&frame, OFFSET_MAC_DEST)?;

        let mac_source_bytes: [u8; 6] = Self::extract_mac_address(&frame, OFFSET_MAC_SRC)?;

        let (q_tag, ether_type_offset) = Self::extract_q_tag(&frame, OFFSET_TPID)?;

        let ether_type: [u8; 2] = Self::extract_ether_type(&frame, ether_type_offset)?;

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
    fn extract_mac_address(frame: &[u8], offset: usize) -> Result<[u8; 6], EthernetFrameError> {
        if frame.len() < offset + 6 {
            return Err(EthernetFrameError::FrameTooShort(
                frame.len(),
                6,
                "Src/Dest MAC Address".to_string(),
            ));
        }

        frame[offset..offset + 6]
            .try_into()
            .map_err(|e| EthernetFrameError::MacAddressExtractionError { source: e })
    }

    /// Extracts the EtherType from an Ethernet frame.
    ///
    /// The EtherType field in an Ethernet frame identifies the next level protocol
    /// (for example, IPv4 or IPv6). This function extracts the EtherType based on
    /// a given offset.
    ///
    /// # Arguments
    ///
    /// * `frame` - A reference to the slice representing the Ethernet frame.
    /// * `offset` - The starting index in the frame where the EtherType is expected.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a two-byte array representing the EtherType.
    /// In case of an error (like if the frame is too short to contain the EtherType at the given offset),
    /// it returns an `EthernetFrameError`.
    fn extract_ether_type(frame: &[u8], offset: usize) -> Result<[u8; 2], EthernetFrameError> {
        if frame.len() < offset + 2 {
            return Err(EthernetFrameError::FrameTooShort(
                frame.len(),
                2,
                "Ether-Type".to_string(),
            ));
        }

        frame[offset..offset + 2]
            .try_into()
            .map_err(|e| EthernetFrameError::EtherTypeExtractionError { source: e })
    }

    /// Extracts the Q-Tag (VLAN tag) from an Ethernet frame, if present.
    ///
    /// The Q-Tag is an optional 4-byte field in an Ethernet frame that signifies
    /// VLAN membership and priority information. The first two bytes of this tag
    /// are typically `0x8100`, which is used to indicate its presence.
    ///
    /// # Arguments
    ///
    /// * `frame`: A slice representing the Ethernet frame.
    /// * `offset`: The starting position in the frame where the Q-Tag might be present.
    ///
    /// # Returns
    ///
    /// If successful, this function returns a tuple containing:
    /// 1. An `Option<[u8; 4]>` representing the Q-Tag bytes if present; `None` otherwise.
    /// 2. The next reading offset after the Q-Tag (or after where it would have been, if not present).
    ///
    /// If there's an error, it returns an `EthernetFrameError`.
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    /// - The frame is too short to contain the expected Q-Tag bytes.
    /// - There's an issue extracting the Q-Tag bytes.
    ///
    fn extract_q_tag(
        frame: &[u8],
        offset: usize,
    ) -> Result<(Option<[u8; 4]>, usize), EthernetFrameError> {
        if frame.len() < offset + 4 {
            return Err(EthernetFrameError::FrameTooShort(
                frame.len(),
                4,
                "Q-Tag".to_string(),
            ));
        }

        match &frame[offset..offset + 2] {
            [81, 00] => {
                let q_tag_bytes: [u8; 4] = frame[offset..offset + 4]
                    .try_into()
                    .map_err(|e| EthernetFrameError::QTagExtractionError { source: e })?;
                Ok((Some(q_tag_bytes), offset + 4))
            }
            _ => Ok((None, offset)),
        }
    }
}
