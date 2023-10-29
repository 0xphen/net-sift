mod mock_data;

use mock_data::{
    generate_ipv6_mock_packet, generate_tcp_packets_with_options, DEFAULT_DEST_ADDRESS,
    DEFAULT_SRC_ADDRESS, MOCK_MALFORMED_PACKET,
};
use net_sift::parsers::{
    definitions::{DeepParser, IPType, LayeredData},
    errors::ParserError,
    ipv6::{Ipv6Packet, Ipv6PacketHeader},
};

use std::net::Ipv6Addr;

struct IPv6Values {
    expected_version: u8,
    expected_traffic_class: u8,
    expected_flow_label: u32,
    expected_payload_length: u16,
    expected_next_header: IPType,
    expected_hop_limit: u8,
    expected_source_address: Ipv6Addr,
    expected_destination_address: Ipv6Addr,
    expected_payload: Vec<u8>,
}

impl From<IPv6Values> for Ipv6Packet {
    fn from(value: IPv6Values) -> Ipv6Packet {
        Ipv6Packet {
            header: Ipv6PacketHeader {
                version: value.expected_version,
                traffic_class: value.expected_traffic_class,
                flow_label: value.expected_flow_label,
                payload_length: value.expected_payload_length,
                next_header: value.expected_next_header,
                hop_limit: value.expected_hop_limit,
                source_address: value.expected_source_address,
                destination_address: value.expected_destination_address,
            },

            data: Box::new(LayeredData::Payload(value.expected_payload)),
        }
    }
}

fn expected_ipv6() -> IPv6Values {
    IPv6Values {
        expected_version: 6,
        expected_traffic_class: 167,
        expected_flow_label: 662527,
        expected_payload_length: 10,
        expected_next_header: IPType::from(6),
        expected_hop_limit: 100,
        expected_source_address: addr(&DEFAULT_SRC_ADDRESS),
        expected_destination_address: addr(&DEFAULT_DEST_ADDRESS),
        expected_payload: generate_tcp_packets_with_options(),
    }
}

fn validate_ipv6(ipv6: Ipv6Packet, expected_ipv6: IPv6Values) {
    let expected_ipv6 = Ipv6Packet::from(expected_ipv6);
    assert_eq!(ipv6, expected_ipv6);
}

fn addr(v: &[u8; 16]) -> Ipv6Addr {
    let mut bytes: [u16; 8] = Default::default();

    for i in 0..8 {
        bytes[i] = u16::from_be_bytes([v[i * 2], v[i * 2 + 1]]);
    }

    Ipv6Addr::from(bytes)
}

// TESTS

#[test]
fn can_parse_ipv6_packet() {
    let packets = generate_ipv6_mock_packet();
    let ipv6 = Ipv6Packet::from_bytes(&packets);

    validate_ipv6(ipv6.unwrap(), expected_ipv6())
}

#[test]
fn fail_if_packet_is_too_short() {
    let result = Ipv6Packet::from_bytes(&MOCK_MALFORMED_PACKET);

    assert!(matches!(result, Err(ParserError::InvalidLength)))
}

#[test]
fn can_parse_layered_data() {
    let packets = generate_ipv6_mock_packet();

    let ipv6_packet = Ipv6Packet::from_bytes(&packets).unwrap();
    let layered_data = ipv6_packet.parse_next_layer().unwrap();

    match layered_data {
        LayeredData::Ipv6Data(v) => match *v.data {
            LayeredData::TcpData(_) => {}
            _ => panic!("Invalid nested layered data"),
        },
        _ => panic!("Invalid layered data"),
    };
}
