use net_sift::parsers::{
    definitions::DeepParser, definitions::LayeredData, errors::ParserError, udp::UdpDatagram,
};

const DEFAULT_PACKET: [u8; 14] = [12, 255, 100, 15, 0, 14, 8, 5, 7, 90, 100, 100, 255, 9];

#[test]
fn can_create_udp() {
    let udp = UdpDatagram::from_bytes(&DEFAULT_PACKET).unwrap();
    assert_eq!(udp.header.source_port, 3327);
    assert_eq!(udp.header.destination_port, 25615);
    assert_eq!(udp.header.length, 14);
    assert_eq!(udp.header.checksum, 2053);
    assert_eq!(
        udp.data,
        Box::new(LayeredData::Payload([7, 90, 100, 100, 255, 9].to_vec()))
    );
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = UdpDatagram::from_bytes(&[9, 12, 34, 5]);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}

#[test]
fn can_parse_layered_data() {
    let udp_datagram = UdpDatagram::from_bytes(&DEFAULT_PACKET).unwrap();
    let layered_data = udp_datagram.parse_next_layer().unwrap();

    assert_eq!(layered_data, LayeredData::UDP(&udp_datagram));
}
