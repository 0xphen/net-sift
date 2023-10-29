mod mock_data;

use mock_data::{
    generate_ethernet_mock_packets, generate_ipv6_mock_packet, DEFAULT_DEST_MAC,
    DEFAULT_ETHER_TYPE, DEFAULT_Q_TAG, DEFAULT_SRC_MAC, INVALID_ETHER_TYPE, MOCK_MALFORMED_PACKET,
};
use net_sift::parsers::{
    definitions::{DeepParser, EtherType, LayeredData},
    errors::ParserError,
    ethernet_frame::EthernetFrame,
};

fn validate_ethernet_frame(frame: EthernetFrame, expected_values: &EthernetFrameValues) {
    assert_eq!(
        frame.header.mac_destination.to_string(),
        expected_values.expected_mac_destination_string
    );
    assert_eq!(
        frame.header.mac_destination.0,
        expected_values.expected_mac_destination
    );

    assert_eq!(
        frame.header.mac_source.to_string(),
        expected_values.expected_mac_source_string
    );
    assert_eq!(
        frame.header.mac_source.0,
        expected_values.expected_mac_source
    );

    assert_eq!(frame.header.ether_type, expected_values.expected_ether_type);
    assert_eq!(frame.header.q_tag, expected_values.expected_q_tag);
    assert_eq!(
        frame.data,
        Box::new(LayeredData::Payload(
            expected_values.expected_payload.to_vec()
        ))
    );
}

struct EthernetFrameValues {
    expected_mac_destination_string: &'static str,
    expected_mac_destination: [u8; 6],
    expected_mac_source_string: &'static str,
    expected_mac_source: [u8; 6],
    expected_ether_type: EtherType,
    expected_q_tag: Option<u32>,
    expected_payload: Vec<u8>,
}

#[test]
fn can_parse_ethernet_frame_without_qtag() {
    let frame = generate_ethernet_mock_packets(None, DEFAULT_ETHER_TYPE);

    let ethernet_frame = EthernetFrame::from_bytes(&frame).unwrap();

    let expected_values = EthernetFrameValues {
        expected_mac_destination_string: "0C:19:3C:FF:58:0C",
        expected_mac_destination: DEFAULT_DEST_MAC,
        expected_mac_source_string: "6C:64:13:19:C8:C7",
        expected_mac_source: DEFAULT_SRC_MAC,
        expected_ether_type: EtherType::from(u16::from_be_bytes(DEFAULT_ETHER_TYPE)),
        expected_q_tag: None,
        expected_payload: generate_ipv6_mock_packet(),
    };

    validate_ethernet_frame(ethernet_frame, &expected_values);
}

#[test]
fn can_parse_ethernet_frame_with_qtag() {
    let frame = generate_ethernet_mock_packets(Some(DEFAULT_Q_TAG), DEFAULT_ETHER_TYPE);

    let ethernet_frame = EthernetFrame::from_bytes(&frame).unwrap();

    let expected_values = EthernetFrameValues {
        expected_mac_destination_string: "0C:19:3C:FF:58:0C",
        expected_mac_destination: DEFAULT_DEST_MAC,
        expected_mac_source_string: "6C:64:13:19:C8:C7",
        expected_mac_source: DEFAULT_SRC_MAC,
        expected_ether_type: EtherType::from(u16::from_be_bytes(DEFAULT_ETHER_TYPE)),
        expected_q_tag: Some(2164261398),
        expected_payload: generate_ipv6_mock_packet(),
    };

    validate_ethernet_frame(ethernet_frame, &expected_values);
}

#[test]
fn fails_if_bad_ether_type() {
    let frame = generate_ethernet_mock_packets(None, INVALID_ETHER_TYPE);

    let result = EthernetFrame::from_bytes(&frame);

    assert!(matches!(result, Err(ParserError::InvalidEtherType)))
}

#[test]
fn fails_if_frame_is_malformed() {
    let result = EthernetFrame::from_bytes(&MOCK_MALFORMED_PACKET);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}

#[test]
fn can_parse_layered_data() {
    let frame = generate_ethernet_mock_packets(Some(DEFAULT_Q_TAG), DEFAULT_ETHER_TYPE);

    let ethernet_frame = EthernetFrame::from_bytes(&frame).unwrap();
    let layered_data = ethernet_frame.parse_next_layer().unwrap();

    match layered_data {
        LayeredData::EthernetFrameData(v) => match *v.data {
            LayeredData::Ipv6Data(_) => {}
            _ => panic!("Invalid nested layered data"),
        },
        _ => panic!("Invalid layered data"),
    };
}
