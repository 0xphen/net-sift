mod mock_data;

use mock_data::{
    generate_ipv4_mock_packets, generate_tcp_packets_with_options, DEFAULT_IPV4_OPTIONS,
    DEFAULT_TCP_PROTOCOL, MOCK_MALFORMED_PACKET,
};
use net_sift::parsers::{
    definitions::{DeepParser, LayeredData},
    errors::ParserError,
    ipv4::IPType,
    ipv4::Ipv4Packet,
};

use std::net::Ipv4Addr;

struct IPV4Values {
    expected_version: u8,
    expected_type_of_service: u8,
    expected_ihl: u8,
    expected_total_length: u16,
    expected_id: u16,
    expected_flags: u8,
    expected_fragment_offset: u16,
    expected_ttl: u8,
    expected_protocol: IPType,
    expected_header_checksum: u16,
    expected_source_address: std::net::Ipv4Addr,
    expected_destination_address: std::net::Ipv4Addr,
    expected_options: Option<Vec<u8>>,
    expected_payload: Vec<u8>,
}

fn validate_ipv4(packet: Ipv4Packet, expected_packet: IPV4Values) {
    println!(
        "{:?} <=> {:?}",
        packet.header.options, expected_packet.expected_options
    );
    assert!(packet.header.version == expected_packet.expected_version);
    assert!(packet.header.internet_header_length == expected_packet.expected_ihl);
    assert!(packet.header.type_of_service == expected_packet.expected_type_of_service);
    assert!(packet.header.total_length == expected_packet.expected_total_length);
    assert!(packet.header.identification == expected_packet.expected_id);
    assert!(packet.header.flags == expected_packet.expected_flags);
    assert!(packet.header.fragment_offset == expected_packet.expected_fragment_offset);
    assert!(packet.header.time_to_live == expected_packet.expected_ttl);
    assert!(packet.header.protocol == expected_packet.expected_protocol);
    assert!(packet.header.header_checksum == expected_packet.expected_header_checksum);
    assert!(packet.header.source_address == expected_packet.expected_source_address);
    assert!(packet.header.destination_address == expected_packet.expected_destination_address);
    assert!(packet.header.options == expected_packet.expected_options);
    assert!(
        packet.data
            == Box::new(LayeredData::Payload(
                expected_packet.expected_payload.to_vec()
            ))
    );
}

// TESTS

#[test]
fn can_create_ipv4_without_options() {
    let packets = generate_ipv4_mock_packets(DEFAULT_TCP_PROTOCOL, None);
    let ipv4 = Ipv4Packet::from_bytes(&packets).unwrap();

    let expected_packet = IPV4Values {
        expected_version: 8,
        expected_type_of_service: 15,
        expected_ihl: 5,
        expected_total_length: packets.len() as u16,
        expected_id: 2078,
        expected_flags: 5,
        expected_fragment_offset: 5840,
        expected_ttl: 60,
        expected_protocol: IPType::from(6),
        expected_header_checksum: 25612,
        expected_source_address: Ipv4Addr::new(100, 127, 60, 5),
        expected_destination_address: Ipv4Addr::new(30, 44, 8, 50),
        expected_options: None,
        expected_payload: generate_tcp_packets_with_options(),
    };

    validate_ipv4(ipv4, expected_packet)
}

#[test]
fn can_parse_ipv4_packet_with_options() {
    let packets = generate_ipv4_mock_packets(DEFAULT_TCP_PROTOCOL, Some(&DEFAULT_IPV4_OPTIONS));

    let ipv4 = Ipv4Packet::from_bytes(&packets).unwrap();

    let expected_packet = IPV4Values {
        expected_version: 8,
        expected_type_of_service: 15,
        expected_ihl: 6,
        expected_total_length: packets.len() as u16,
        expected_id: 2078,
        expected_flags: 5,
        expected_fragment_offset: 5840,
        expected_ttl: 60,
        expected_protocol: IPType::from(6),
        expected_header_checksum: 25612,
        expected_source_address: Ipv4Addr::new(100, 127, 60, 5),
        expected_destination_address: Ipv4Addr::new(30, 44, 8, 50),
        expected_options: Some(DEFAULT_IPV4_OPTIONS.to_vec()),
        expected_payload: generate_tcp_packets_with_options(),
    };

    validate_ipv4(ipv4, expected_packet)
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = Ipv4Packet::from_bytes(&MOCK_MALFORMED_PACKET);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}

#[test]
fn can_parse_layered_data() {
    let packets = generate_ipv4_mock_packets(DEFAULT_TCP_PROTOCOL, Some(&DEFAULT_IPV4_OPTIONS));

    let ipv4_packet = Ipv4Packet::from_bytes(&packets).unwrap();
    let layered_data = ipv4_packet.parse_next_layer().unwrap();

    match layered_data {
        LayeredData::Ipv4Data(v) => match *v.data {
            LayeredData::TcpData(_) => {}
            _ => panic!("Invalid nested layered data"),
        },
        _ => panic!("Invalid layered data"),
    };
}
