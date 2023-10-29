// Main module imports necessary for parsing operations.
use super::{
    errors::ParserError, ethernet_frame::EthernetFrame, icmp::IcmpPacket, ipv4::Ipv4Packet,
    ipv6::Ipv6Packet, tcp::TcpSegment, udp::UdpDatagram,
};

/// Represents the various types of Internet Protocol (IP) that might be encountered.
#[derive(Debug, PartialEq)]
pub enum IPType {
    TCP,       // Transmission Control Protocol
    UDP,       // User Datagram Protocol
    ICMP,      // Internet Control Message Protocol
    Other(u8), // Placeholder for other types not explicitly handled
}

// Enables conversion from a byte, making it easier to handle values from raw data.
impl From<u8> for IPType {
    fn from(byte: u8) -> IPType {
        match byte {
            1 => IPType::ICMP,
            6 => IPType::TCP,
            17 => IPType::UDP,
            _ => IPType::Other(byte), // Any other type is still preserved.
        }
    }
}

/// Defines the types of protocols expected in the Ethernet frame's EtherType field.
#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,       // Internet Protocol version 4
    IPv6,       // Internet Protocol version 6
    ARP,        // Address Resolution Protocol
    Other(u16), // Catch-all for other EtherTypes
}

// Simplifies the creation of `EtherType` instances from raw numerical values.
impl From<u16> for EtherType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,
            0x86DD => Self::IPv6,
            0x0806 => Self::ARP,
            other => Self::Other(other), // Other values are still retained.
        }
    }
}

/// A trait that defines the functionality for deep packet inspection, ensuring a consistent interface.
pub trait DeepParser {
    /// Analyzes the encapsulated data within the packet, returning a more structured form.
    ///
    /// # Returns
    ///
    /// * `Ok(LayeredData)` - Parsed packet data encapsulated in a structured type.
    /// * `Err(ParserError)` - An error occurred during parsing, encapsulated in a `ParserError`.
    fn parse_next_layer(self) -> Result<LayeredData, ParserError>;
}

/// Represents the various forms of data that can be parsed from the network layers.
#[derive(Debug, PartialEq)]
pub enum LayeredData {
    Payload(Vec<u8>),                 // Raw data payload
    IcmpData(IcmpPacket),             // Data from an ICMP packet
    UdpData(UdpDatagram),             // Data from a UDP datagram
    TcpData(TcpSegment),              // Data from a TCP segment
    Ipv4Data(Ipv4Packet),             // Data from an IPv4 packet
    Ipv6Data(Ipv6Packet),             // Data from an IPv6 packet
    EthernetFrameData(EthernetFrame), // Data from a complete Ethernet frame
    Empty,                            // Represents a lack of data or an empty packet
}
