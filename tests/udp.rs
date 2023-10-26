use net_sift::parsers::{errors::ParserError, udp::UDP};

const DEFAULT_PACKET: [u8; 14] = [12, 255, 100, 15, 0, 14, 8, 5, 7, 90, 100, 100, 255, 9];

#[test]
fn can_create_udp() {
    let udp = UDP::from_bytes(&DEFAULT_PACKET).unwrap();
    assert_eq!(udp.source_port, 3327);
    assert_eq!(udp.destination_port, 25615);
    assert_eq!(udp.length, 14);
    assert_eq!(udp.checksum, 2053);
    assert_eq!(udp.data, [7, 90, 100, 100, 255, 9].to_vec());
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = UDP::from_bytes(&[9, 12, 34, 5]);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}
