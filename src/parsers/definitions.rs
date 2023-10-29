use super::{
    errors::ParserError, icmp::IcmpPacket, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpSegment,
    udp::UdpDatagram,
};

#[derive(Debug, PartialEq)]
pub enum IPType {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl From<u8> for IPType {
    fn from(byte: u8) -> IPType {
        match byte {
            1 => IPType::ICMP,
            6 => IPType::TCP,
            17 => IPType::UDP,
            _ => IPType::Other(byte),
        }
    }
}

/// `DeepParser` is a trait intended for objects representing network packets.
/// It provides a method to parse the encapsulated data and return it in a structured format.
pub trait DeepParser {
    /// Parses the packet data to extract further encapsulated layers.
    ///
    /// # Returns
    /// * `Ok(LayeredData)` if the parsing is successful and the data is encapsulated within.
    /// * `Err(ParserError)` if there is an issue with parsing.
    fn parse_next_layer(self) -> Result<LayeredData, ParserError>;
}

#[derive(Debug, PartialEq)]
pub enum LayeredData {
    Payload(Vec<u8>),
    IcmpData(IcmpPacket),
    UdpData(UdpDatagram),
    TcpData(TcpSegment),
    Ipv4Data(Ipv4Packet),
    Ipv6Data(Ipv6Packet),
    Empty,
}
