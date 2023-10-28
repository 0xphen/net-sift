use net_sift::parsers::{errors::ParserError, ipv6::Ipv6Packet};

use std::net::Ipv6Addr;

const MOCK_MALFORMED_PACKET: [u8; 19] = [
    12, 25, 60, 255, 88, 12, 108, 100, 19, 25, 200, 199, 81, 0, 2, 22, 8, 0, 12,
];

const DEFAULT_VERSION_TRAFFIC_CLASS_FLOW_LABEL: [u8; 4] = [106, 122, 27, 255];
const DEFAULT_PYLOAD_LENGTH_NEXT_HEADER_HOP_LIMIT: [u8; 4] = [0, 10, 15, 100];
const DEFAULT_SRC_ADDRESS: [u8; 16] = [
    0, 0, 1, 123, 43, 12, 100, 255, 255, 255, 10, 21, 45, 12, 12, 12,
];
const DEFAULT_DEST_ADDRESS: [u8; 16] = [
    10, 90, 1, 123, 43, 12, 100, 255, 255, 255, 255, 21, 45, 100, 12, 12,
];
const DEFAULT_PAYLOAD: [u8; 10] = [255, 12, 34, 87, 5, 0, 25, 12, 10, 90];

struct IPv6Values {
    expected_version: u8,
    expected_traffic_class: u8,
    expected_flow_label: u32,
    expected_payload_length: u16,
    expected_next_header: u8,
    expected_hop_limit: u8,
    expected_source_address: Ipv6Addr,
    expected_destination_address: Ipv6Addr,
    expected_payload: Vec<u8>,
}

impl From<IPv6Values> for Ipv6Packet {
    fn from(value: IPv6Values) -> Ipv6Packet {
        Ipv6Packet {
            version: value.expected_version,
            traffic_class: value.expected_traffic_class,
            flow_label: value.expected_flow_label,
            payload_length: value.expected_payload_length,
            next_header: value.expected_next_header,
            hop_limit: value.expected_hop_limit,
            source_address: value.expected_source_address,
            destination_address: value.expected_destination_address,
            payload: value.expected_payload,
        }
    }
}

fn generate_mock_packet() -> Vec<u8> {
    let mut packets: Vec<u8> = vec![0; 50];

    packets[0..4].copy_from_slice(&DEFAULT_VERSION_TRAFFIC_CLASS_FLOW_LABEL);

    packets[4..8].copy_from_slice(&DEFAULT_PYLOAD_LENGTH_NEXT_HEADER_HOP_LIMIT);

    packets[8..24].copy_from_slice(&DEFAULT_SRC_ADDRESS);
    packets[24..40].copy_from_slice(&DEFAULT_DEST_ADDRESS);

    packets[40..50].copy_from_slice(&DEFAULT_PAYLOAD);

    return packets;
}

fn expected_ipv6() -> IPv6Values {
    IPv6Values {
        expected_version: 6,
        expected_traffic_class: 167,
        expected_flow_label: 662527,
        expected_payload_length: 10,
        expected_next_header: 15,
        expected_hop_limit: 100,
        expected_source_address: addr(&DEFAULT_SRC_ADDRESS),
        expected_destination_address: addr(&DEFAULT_DEST_ADDRESS),
        expected_payload: DEFAULT_PAYLOAD.to_vec(),
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
    let packets = generate_mock_packet();
    let ipv6 = Ipv6Packet::from_bytes(&packets);

    validate_ipv6(ipv6.unwrap(), expected_ipv6())
}

#[test]
fn fail_if_packet_is_too_short() {
    let result = Ipv6Packet::from_bytes(&MOCK_MALFORMED_PACKET);

    assert!(matches!(result, Err(ParserError::InvalidLength)))
}
