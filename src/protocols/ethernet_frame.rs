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

const MAC_ADDRESS_BYTES: usize = 6;

/// Represents a MAC address.
#[derive(Debug)]
struct MacAddress([u8; MAC_ADDRESS_BYTES]);

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

    /// Converts a vector of bytes into a MAC address array.
    ///
    /// This function expects the input vector to have exactly `MAC_ADDRESS_BYTES` length
    /// and will panic if the size is not correct.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A vector containing bytes of a MAC address.
    ///
    /// # Returns
    ///
    /// * A byte array of size `MAC_ADDRESS_BYTES` representing a MAC address.
    ///
    /// # Panics
    ///
    /// * If the length of the input vector is not equal to `MAC_ADDRESS_BYTES`.
    pub fn to_mac_array(bytes: Vec<u8>) -> [u8; 6] {
        if bytes.len() != MAC_ADDRESS_BYTES {
            panic!("Invalid MAC address size");
        }

        bytes.try_into().expect("Failed to convert vec to array")
    }
}

#[derive(Debug)]
pub struct EthernetFrame {
    mac_destination: MacAddress,
    mac_source: MacAddress,
    // ether_type: [u8; 2],
}

impl EthernetFrame {
    pub fn new(data: Vec<u8>) -> Self {
        EthernetFrame {
            mac_destination: MacAddress::from_bytes(MacAddress::to_mac_array(
                EthernetFrame::extract_subslice_as_vec(&data, 0, 6),
            )),
            mac_source: MacAddress::from_bytes(MacAddress::to_mac_array(
                EthernetFrame::extract_subslice_as_vec(&data, 6, 6),
            )),
        }
    }

    /// Extracts a sub-slice from a given vector and returns it as a new vector.
    ///
    /// # Arguments
    ///
    /// * `vec` - The source vector.
    /// * `start` - The starting index of the slice.
    /// * `len` - The length of the slice.
    ///
    /// # Returns
    ///
    /// * A new vector containing the sub-slice.
    ///
    /// # Panics
    ///
    /// * If the specified slice range is out of bounds for the given vector.

    pub fn extract_subslice_as_vec(vec: &Vec<u8>, start: usize, len: usize) -> Vec<u8> {
        (vec[start..(start + len)])
            .try_into()
            .expect("Failed to convert slice to array")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks;

    #[test]
    fn create_ethernet_frame_from_packet() {
        let frame = EthernetFrame::new(mocks::MOCK_PACKET.to_vec());
    }
}
