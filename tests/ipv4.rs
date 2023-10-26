use net_sift::parsers::{errors::ParserError, ipv4::IPType, ipv4::Ipv4Packet};

use std::net::Ipv4Addr;

const MOCK_MALFORMED_PACKET: [u8; 19] = [
    12, 25, 60, 255, 88, 12, 108, 100, 19, 25, 200, 199, 81, 0, 2, 22, 8, 0, 12,
];

const DEFAULT_VERSION_IHL_WITHOUT_OPTIONS: [u8; 1] = [133];
const DEFAULT_VERSION_IHL_WITH_OPTIONS: [u8; 1] = [134];
const DEFAULT_TOS: [u8; 1] = [15];
const DEFAULT_TOTAL_LENGTH_WITHOUT_OPTIONS: [u8; 2] = [0, 25];
const DEFAULT_TOTAL_LENGTH_WITH_OPTIONS: [u8; 2] = [0, 29];
const DEFAULT_IDENTIFICATION: [u8; 2] = [8, 30];
const DEFAULT_FLAGS_FRAGMENT: [u8; 2] = [182, 208];
const DEFAULT_TTL: [u8; 1] = [60];
const DEFAULT_PROTOCOL: [u8; 1] = [6];
const DEFAULT_HEADER_CHECKSUM: [u8; 2] = [100, 12];
const DEFAULT_SRC_ADDR: [u8; 4] = [100, 127, 60, 5];
const DEFAULT_DEST_ADDR: [u8; 4] = [30, 44, 8, 50];
const DEFAULT_OPTIONS: [u8; 4] = [30, 44, 50, 12];
const DEFAULT_PAYLOAD: [u8; 5] = [50, 12, 45, 19, 23];

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
    expected_payload: &'static [u8],
}

fn generate_mock_packet(
    version_ihl: [u8; 1],
    type_of_service: [u8; 1],
    total_length: [u8; 2],
    id: [u8; 2],
    flags_fragment: [u8; 2],
    time_to_live: [u8; 1],
    protocol: [u8; 1],
    header_checksum: [u8; 2],
    source_address: [u8; 4],
    destination_address: [u8; 4],
    options: Option<&[u8]>,
    payload: &[u8],
) -> Vec<u8> {
    let packet_size = match options {
        Some(ref v) => 20 + v.len() + payload.len(),
        _ => 20 + payload.len(),
    };

    let mut packets: Vec<u8> = vec![0; packet_size];

    packets[0..1].copy_from_slice(&version_ihl);
    packets[1..2].copy_from_slice(&type_of_service);
    packets[2..4].copy_from_slice(&total_length);
    packets[4..6].copy_from_slice(&id);
    packets[6..8].copy_from_slice(&flags_fragment);
    packets[8..9].copy_from_slice(&time_to_live);
    packets[9..10].copy_from_slice(&protocol);
    packets[10..12].copy_from_slice(&header_checksum);
    packets[12..16].copy_from_slice(&source_address);
    packets[16..20].copy_from_slice(&destination_address);

    match options {
        Some(v) => {
            let options_end = 20 + v.len();
            packets[20..options_end].copy_from_slice(&v);
            packets[options_end..(options_end + payload.len())].copy_from_slice(&payload);
        }
        _ => packets[20..(20 + payload.len())].copy_from_slice(&payload),
    }

    packets
}

fn validate_ipv4(packet: Ipv4Packet, expected_packet: IPV4Values) {
    assert!(packet.version == expected_packet.expected_version);
    assert!(packet.internet_header_length == expected_packet.expected_ihl);
    assert!(packet.type_of_service == expected_packet.expected_type_of_service);
    assert!(packet.total_length == expected_packet.expected_total_length);
    assert!(packet.identification == expected_packet.expected_id);
    assert!(packet.flags == expected_packet.expected_flags);
    assert!(packet.fragment_offset == expected_packet.expected_fragment_offset);
    assert!(packet.time_to_live == expected_packet.expected_ttl);
    assert!(packet.protocol == expected_packet.expected_protocol);
    assert!(packet.header_checksum == expected_packet.expected_header_checksum);
    assert!(packet.source_address == expected_packet.expected_source_address);
    assert!(packet.destination_address == expected_packet.expected_destination_address);
    assert!(packet.options == expected_packet.expected_options);
    assert!(packet.payload == expected_packet.expected_payload);
}

// TESTS

#[test]
fn can_create_ipv4_without_options() {
    let packets = generate_mock_packet(
        DEFAULT_VERSION_IHL_WITHOUT_OPTIONS,
        DEFAULT_TOS,
        DEFAULT_TOTAL_LENGTH_WITHOUT_OPTIONS,
        DEFAULT_IDENTIFICATION,
        DEFAULT_FLAGS_FRAGMENT,
        DEFAULT_TTL,
        DEFAULT_PROTOCOL,
        DEFAULT_HEADER_CHECKSUM,
        DEFAULT_SRC_ADDR,
        DEFAULT_DEST_ADDR,
        None,
        &DEFAULT_PAYLOAD,
    );

    let ipv4 = Ipv4Packet::from_bytes(&packets).unwrap();

    let expected_packet = IPV4Values {
        expected_version: 8,
        expected_type_of_service: 15,
        expected_ihl: 5,
        expected_total_length: 25,
        expected_id: 2078,
        expected_flags: 5,
        expected_fragment_offset: 5840,
        expected_ttl: 60,
        expected_protocol: IPType::from(6),
        expected_header_checksum: 25612,
        expected_source_address: Ipv4Addr::new(100, 127, 60, 5),
        expected_destination_address: Ipv4Addr::new(30, 44, 8, 50),
        expected_options: None,
        expected_payload: &[50, 12, 45, 19, 23],
    };

    validate_ipv4(ipv4, expected_packet)
}

#[test]
fn can_create_ipv4_with_options() {
    let packets = generate_mock_packet(
        DEFAULT_VERSION_IHL_WITH_OPTIONS,
        DEFAULT_TOS,
        DEFAULT_TOTAL_LENGTH_WITH_OPTIONS,
        DEFAULT_IDENTIFICATION,
        DEFAULT_FLAGS_FRAGMENT,
        DEFAULT_TTL,
        DEFAULT_PROTOCOL,
        DEFAULT_HEADER_CHECKSUM,
        DEFAULT_SRC_ADDR,
        DEFAULT_DEST_ADDR,
        Some(&DEFAULT_OPTIONS),
        &DEFAULT_PAYLOAD,
    );

    let ipv4 = Ipv4Packet::from_bytes(&packets).unwrap();

    let expected_packet = IPV4Values {
        expected_version: 8,
        expected_type_of_service: 15,
        expected_ihl: 6,
        expected_total_length: 29,
        expected_id: 2078,
        expected_flags: 5,
        expected_fragment_offset: 5840,
        expected_ttl: 60,
        expected_protocol: IPType::from(6),
        expected_header_checksum: 25612,
        expected_source_address: Ipv4Addr::new(100, 127, 60, 5),
        expected_destination_address: Ipv4Addr::new(30, 44, 8, 50),
        expected_options: Some(DEFAULT_OPTIONS.to_vec()),
        expected_payload: &[50, 12, 45, 19, 23],
    };

    validate_ipv4(ipv4, expected_packet)
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = Ipv4Packet::from_bytes(&MOCK_MALFORMED_PACKET);

    let malformed_packet_size = MOCK_MALFORMED_PACKET.to_vec().len();

    assert!(matches!(result, Err(ParserError::InvalidLength)))
}
