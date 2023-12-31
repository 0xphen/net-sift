mod mock_data;

use mock_data::{
    generate_tcp_packets_with_options, generate_tcp_packets_without_options, DEFAULT_DATA,
    DEFAULT_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW,
    DEFAULT_ZERO_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW, MOCK_MALFORMED_PACKET,
};
use net_sift::parsers::{
    definitions::DeepParser, definitions::LayeredData, errors::ParserError, tcp,
};

// fn generate_mock_segment(data_offset_reserved_flags_window: [u8; 4]) -> Vec<u8> {
//     let v = u32::from_be_bytes(data_offset_reserved_flags_window);
//     let l = v >> 28;
//     let cap: usize = (l * 32 / 8) as usize + DEFAULT_DATA.len();

//     let mut segment: Vec<u8> = vec![0; cap];

//     segment[0..4].copy_from_slice(&DEFAULT_SRC_DEST_PORT);
//     segment[4..8].copy_from_slice(&DEFAULT_SEQUENCE_NUMBER);
//     segment[8..12].copy_from_slice(&DEFAULT_ACK_NUMBER);
//     segment[12..16].copy_from_slice(&data_offset_reserved_flags_window);
//     segment[16..20].copy_from_slice(&DEFAULT_CHECKSUM_URGENT_POINTER);

//     if l == 5 {
//         segment[20..28].copy_from_slice(&DEFAULT_DATA);
//     } else if l > 5 {
//         segment[20..24].copy_from_slice(&DEFAULT_OPTIONS);
//         segment[24..32].copy_from_slice(&DEFAULT_DATA);
//     }

//     segment
// }

struct TcpValues {
    expected_src_port: u16,
    expected_dest_port: u16,
    expected_seq_number: u32,
    expected_ack_number: u32,
    expected_data_offset: u8,
    expected_reserved: u8,
    expected_flags: tcp::Flags,
    expected_window_size: u16,
    expected_checksum: u16,
    expected_urg_pointer: u16,
    expected_data: Vec<u8>,
}

impl From<TcpValues> for tcp::TcpSegment {
    fn from(value: TcpValues) -> tcp::TcpSegment {
        tcp::TcpSegment {
            header: tcp::TcpSegmentHeader {
                source_port: value.expected_src_port,
                destination_port: value.expected_dest_port,
                sequence_number: value.expected_seq_number,
                acknowledgment_value: value.expected_ack_number,
                data_offset: value.expected_data_offset,
                reserved: value.expected_reserved,
                flags: value.expected_flags,
                window_size: value.expected_window_size,
                checksum: value.expected_checksum,
                urg_pointer: value.expected_urg_pointer,
            },

            data: Box::new(LayeredData::Payload(value.expected_data)),
        }
    }
}

fn expected_tcp_values(expected_data_offset: u8) -> TcpValues {
    TcpValues {
        expected_src_port: 53145,
        expected_dest_port: 80,
        expected_seq_number: 1000,
        expected_ack_number: 1500,
        expected_data_offset,
        expected_reserved: 0,
        expected_flags: tcp::Flags::new(255),
        expected_window_size: 5000,
        expected_checksum: 18459,
        expected_urg_pointer: 1345,
        expected_data: DEFAULT_DATA.to_vec(),
    }
}

fn validate_tcp(tcp: tcp::TcpSegment, expected_tcp: TcpValues) {
    let expected_tcp = tcp::TcpSegment::from(expected_tcp);
    assert_eq!(tcp, expected_tcp);
}

// TEST

#[test]
fn can_parse_tcp_packet_without_options() {
    let segment = generate_tcp_packets_without_options();
    let tcp_segment = tcp::TcpSegment::from_bytes(&segment).unwrap();
    let data_offset =
        (u32::from_be_bytes(DEFAULT_ZERO_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW) >> 28) as u8;

    validate_tcp(tcp_segment, expected_tcp_values(data_offset));
}

#[test]
fn can_parse_tcp_packet_with_options() {
    let segment = generate_tcp_packets_with_options();
    let tcp_segment = tcp::TcpSegment::from_bytes(&segment).unwrap();
    let data_offset =
        (u32::from_be_bytes(DEFAULT_OPTIONS_DATA_OFFSET_RESERVED_FLAGS_WINDOW) >> 28) as u8;

    validate_tcp(tcp_segment, expected_tcp_values(data_offset));
}

#[test]
fn fail_if_segment_is_too_short() {
    let result = tcp::TcpSegment::from_bytes(&MOCK_MALFORMED_PACKET);

    let s = String::from("TCP segment");
    assert!(matches!(result, Err(ParserError::InvalidLength(s))))
}

#[test]
fn can_parse_layered_data() {
    let segment = generate_tcp_packets_with_options();
    let tcp_segment = tcp::TcpSegment::from_bytes(&segment).unwrap();

    let layered_data = tcp_segment.parse_next_layer().unwrap();

    match layered_data {
        LayeredData::TcpData(_) => {}
        _ => panic!("Invalid layered data"),
    };
}
