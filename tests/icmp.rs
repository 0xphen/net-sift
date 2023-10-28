use net_sift::parsers::{errors::ParserError, icmp::IcmpPacket};

const DEFAULT_PACKET: [u8; 12] = [8, 12, 94, 4, 0, 0, 0, 0, 12, 10, 0, 5];

#[test]
fn can_decode_icmp_packet() {
    let icmp_packet = IcmpPacket::from_bytes(&DEFAULT_PACKET).unwrap();
    assert_eq!(icmp_packet.icmp_type, 8);
    assert_eq!(icmp_packet.icmp_code, 12);
    assert_eq!(icmp_packet.checksum, 24068);
    assert_eq!(icmp_packet.data, [12, 10, 0, 5])
}

#[test]
fn fails_if_packet_is_malformed() {
    let result = IcmpPacket::from_bytes(&[9, 12, 34, 5]);
    assert!(matches!(result, Err(ParserError::InvalidLength)))
}
