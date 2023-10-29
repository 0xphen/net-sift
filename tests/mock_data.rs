#[allow(dead_code)]
pub const ICMP_PACKETS: [u8; 12] = [8, 12, 94, 4, 0, 0, 0, 0, 12, 10, 0, 5];

#[allow(dead_code)]
pub const UDP_PACKETS: [u8; 14] = [12, 255, 100, 15, 0, 14, 8, 5, 7, 90, 100, 100, 255, 9];

#[allow(dead_code)]
pub const MOCK_MALFORMED_PACKET: [u8; 19] = [
    12, 25, 60, 255, 88, 12, 108, 100, 19, 25, 200, 199, 81, 0, 2, 22, 8, 0, 12,
];

// TCP Packets
pub const DEFAULT_SRC_DEST_PORT: [u8; 4] = [207, 153, 0, 80];
pub const DEFAULT_SEQUENCE_NUMBER: [u8; 4] = [0, 0, 3, 232];
pub const DEFAULT_ACK_NUMBER: [u8; 4] = [0, 0, 5, 220];
pub const DEFAULT_ZERO_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW: [u8; 4] = [80, 255, 19, 136];
pub const DEFAULT_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW: [u8; 4] = [96, 255, 19, 136];
pub const DEFAULT_CHECKSUM_URGENT_POINTER: [u8; 4] = [72, 27, 5, 65];
pub const DEFAULT_OPTIONS: [u8; 4] = [12, 5, 0, 255];
pub const DEFAULT_DATA: [u8; 8] = [120, 5, 0, 55, 0, 255, 12, 100];

fn cap(data_offset_reserved_flags_window: [u8; 4]) -> usize {
    let v = u32::from_be_bytes(data_offset_reserved_flags_window);
    let l = v >> 28;
    (l * 32 / 8) as usize + DEFAULT_DATA.len()
}

pub fn generate_tcp_packets_without_options() -> Vec<u8> {
    let cap: usize = cap(DEFAULT_ZERO_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW);
    let mut segment: Vec<u8> = vec![0; cap];

    segment[0..4].copy_from_slice(&DEFAULT_SRC_DEST_PORT);
    segment[4..8].copy_from_slice(&DEFAULT_SEQUENCE_NUMBER);
    segment[8..12].copy_from_slice(&DEFAULT_ACK_NUMBER);
    segment[12..16].copy_from_slice(&DEFAULT_ZERO_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW);
    segment[16..20].copy_from_slice(&DEFAULT_CHECKSUM_URGENT_POINTER);
    segment[20..28].copy_from_slice(&DEFAULT_DATA);

    segment
}

pub fn generate_tcp_packets_with_options() -> Vec<u8> {
    let cap: usize = cap(DEFAULT_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW);
    let mut segment: Vec<u8> = vec![0; cap];

    segment[0..4].copy_from_slice(&DEFAULT_SRC_DEST_PORT);
    segment[4..8].copy_from_slice(&DEFAULT_SEQUENCE_NUMBER);
    segment[8..12].copy_from_slice(&DEFAULT_ACK_NUMBER);
    segment[12..16].copy_from_slice(&DEFAULT_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW);
    segment[16..20].copy_from_slice(&DEFAULT_CHECKSUM_URGENT_POINTER);
    segment[20..24].copy_from_slice(&DEFAULT_OPTIONS);
    segment[24..32].copy_from_slice(&DEFAULT_DATA);

    segment
}

// IPV4 Packets
pub const MIN_LENGTH: usize = 20;
pub const DEFAULT_VERSION_IHL_WITHOUT_OPTIONS: [u8; 1] = [133];
pub const DEFAULT_VERSION_IHL_WITH_OPTIONS: [u8; 1] = [134];
pub const DEFAULT_TOS: [u8; 1] = [15];
pub const DEFAULT_IDENTIFICATION: [u8; 2] = [8, 30];
pub const DEFAULT_FLAGS_FRAGMENT: [u8; 2] = [182, 208];
pub const DEFAULT_TTL: [u8; 1] = [60];
pub const DEFAULT_TCP_PROTOCOL: [u8; 1] = [6];
pub const DEFAULT_UDP_PROTOCOL: [u8; 1] = [17];
pub const DEFAULT_ICMP_PROTOCOL: [u8; 1] = [1];
pub const DEFAULT_HEADER_CHECKSUM: [u8; 2] = [100, 12];
pub const DEFAULT_SRC_ADDR: [u8; 4] = [100, 127, 60, 5];
pub const DEFAULT_DEST_ADDR: [u8; 4] = [30, 44, 8, 50];
pub const DEFAULT_IPV4_OPTIONS: [u8; 4] = [30, 44, 50, 12];
pub const DEFAULT_PAYLOAD: [u8; 5] = [50, 12, 45, 19, 23];

pub fn generate_ipv4_mock_packets(protocol: [u8; 1], options: Option<&[u8]>) -> Vec<u8> {
    let payload = generate_tcp_packets_with_options();

    let (options, options_size) = match options {
        Some(v) => (DEFAULT_VERSION_IHL_WITH_OPTIONS, DEFAULT_IPV4_OPTIONS.len()),
        None => (DEFAULT_VERSION_IHL_WITHOUT_OPTIONS, 0),
    };

    let total_length = MIN_LENGTH + payload.len() + options_size;

    let mut packets: Vec<u8> = vec![0; total_length];

    packets[0..1].copy_from_slice(&options);
    packets[1..2].copy_from_slice(&DEFAULT_TOS);
    packets[2..4].copy_from_slice(&u16::to_be_bytes(total_length as u16));
    packets[4..6].copy_from_slice(&DEFAULT_IDENTIFICATION);
    packets[6..8].copy_from_slice(&DEFAULT_FLAGS_FRAGMENT);
    packets[8..9].copy_from_slice(&DEFAULT_TTL);
    packets[9..10].copy_from_slice(&protocol);
    packets[10..12].copy_from_slice(&DEFAULT_HEADER_CHECKSUM);
    packets[12..16].copy_from_slice(&DEFAULT_SRC_ADDR);
    packets[16..20].copy_from_slice(&DEFAULT_DEST_ADDR);

    if options_size > 0 {
        let options_end = 20 + options_size;
        packets[20..options_end].copy_from_slice(&DEFAULT_IPV4_OPTIONS);
        packets[options_end..(options_end + payload.len())].copy_from_slice(&payload);
    } else {
        packets[20..(20 + payload.len())].copy_from_slice(&payload);
    }

    packets
}
