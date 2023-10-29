mod mock_data;

use mock_data::ICMP_PACKETS;

use net_sift::parsers::{
    definitions::DeepParser, definitions::LayeredData, errors::ParserError, icmp::IcmpPacket,
};

#[test]
fn can_decode_icmp_packet() {
    let icmp_packet = IcmpPacket::from_bytes(&ICMP_PACKETS).unwrap();
    assert_eq!(icmp_packet.header.icmp_type, 8);
    assert_eq!(icmp_packet.header.icmp_code, 12);
    assert_eq!(icmp_packet.header.checksum, 24068);
    assert_eq!(
        icmp_packet.data,
        Box::new(LayeredData::Payload([12, 10, 0, 5].to_vec()))
    )
}

#[test]
fn can_parse_layered_data() {
    let icmp_packet = IcmpPacket::from_bytes(&ICMP_PACKETS).unwrap();
    let layered_data = icmp_packet.parse_next_layer().unwrap();

    match layered_data {
        LayeredData::IcmpData(_) => {}
        _ => panic!("Invalid layered data"),
    };
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = IcmpPacket::from_bytes(&[9, 12, 34, 5]);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}
