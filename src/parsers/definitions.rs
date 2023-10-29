use super::{errors::ParserError, icmp::IcmpPacket, tcp::TcpSegment, udp::UdpDatagram};

pub trait DeepParser {
    fn parse_next_layer<'a>(&'a self) -> Result<LayeredData<'a>, ParserError>;
}

#[derive(Debug, PartialEq)]
pub enum LayeredData<'a> {
    Payload(Vec<u8>),
    ICMP(&'a IcmpPacket<'a>),
    UDP(&'a UdpDatagram<'a>),
    TCP(&'a TcpSegment<'a>),
    Empty,
}
