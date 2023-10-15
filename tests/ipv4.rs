use net_sift::protocols::ipv4::IPV4;

const DEFAULT_VERSION_IHL: [u8; 1] = [133];
const DEFAULT_TOS: [u8; 1] = [15];
const DEFAULT_TOTAL_LENGTH_WITHOUT_OPTIONS: [u8; 2] = [0, 30];
const DEFAULT_IDENTIFICATION: [u8; 2] = [8, 30];
const DEFAULT_FLAGS_FRAGMENT: [u8; 2] = [15, 80];
const DEFAULT_TTL: [u8; 1] = [60];
const DEFAULT_PROTOCOL: [u8; 1] = [6];
const DEFAULT_HEADER_CHECKSUM: [u8; 2] = [100, 12];
const DEFAULT_SRC_ADDR: [u8; 4] = [100, 127, 60, 5];
const DEFAULT_DEST_ADDR: [u8; 4] = [30, 44, 8, 50];
const DEFAULT_OPTIONS: [u8; 10] = [30, 44, 0, 50, 12, 45, 159, 45, 21, 100];
const DEFAULT_PAYLOAD: [u8; 5] = [50, 12, 45, 19, 23];

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
    options: Option<Vec<u8>>,
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

fn validate_ipv4(packet: IPV4, expected_packet: IPV4) {
    assert!(packet.version == expected_packet.version);
    assert!(packet.internet_header_length == expected_packet.internet_header_length);
    assert!(packet.type_of_service == expected_packet.type_of_service);
    assert!(packet.total_length == expected_packet.total_length);
    assert!(packet.identification == expected_packet.identification);
    assert!(packet.flags == expected_packet.flags);
    assert!(packet.fragment_offset == expected_packet.fragment_offset);
    assert!(packet.time_to_live == expected_packet.time_to_live);
    assert!(packet.protocol == expected_packet.protocol);
    assert!(packet.header_checksum == expected_packet.header_checksum);
    assert!(packet.source_address == expected_packet.source_address);
    assert!(packet.destination_address == expected_packet.destination_address);
    assert!(packet.options == expected_packet.options);
    assert!(packet.payload == expected_packet.payload);
}

#[test]
fn can_create_ipv4_without_options() {
    let packets = generate_mock_packet(
        DEFAULT_VERSION_IHL,
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

    let ipv4 = IPV4::new(&packets).unwrap();
    //  validate_ipv4(ipv4, expected_packet)
}
